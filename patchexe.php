<?php
require_once "./vendor/autoload.php";
require_once "support/win_pe_file.php";
require_once "support/win_pe_utils.php";

function writeLog($logLevel, $message)
{
    echo $logLevel . ": " . $message . PHP_EOL;
}

$srcfile = "origNostaleClientX.exe";

// Validation is optional but saves loading the entire file into RAM if the file isn't valid.
$result = WinPEFile::ValidateFile($srcfile);
if (!$result["success"]) {
    var_dump($result);

    exit();
}
writeLog("Info", "PE File is valid.");

// Parse the file.
$data = file_get_contents($srcfile);

$options = array('pe_section_data' => true, "pe_directories" => "all");

$winpe = new WinPEFile();
writeLog("Info", "Parsing PE File.");
$result = $winpe->Parse($data, $options);

if (!$result["success"]) {
    var_dump($result);

    exit();
}

// Sanitize the DOS stub.
writeLog("Info", "Sanitize the DOS stub.");
$result = $winpe->SanitizeDOSStub($data);
if (!$result["success"]) {
    var_dump($result);

    exit();
}

// Strip debug directory.
writeLog("Info", "Stripping debug directory info.");
$result = $winpe->ClearDebugDirectory($data);
if (!$result["success"]) {
    var_dump($result);

    exit();
}

// Strip Authenticode certificate(s).
writeLog("Info", "Stripping certificates.");
$result = $winpe->ClearCertificates($data);
if (!$result["success"]) {
    var_dump($result);

    exit();
}

// Update the checksum.
$winpe->UpdateChecksum($data);
writeLog("Info", "Dumping icon.");
$result = WinPEUtils::GetIconResource($winpe);
if (!$result["success"]) {
    var_dump($result);

    exit();
}

WinPEUtils::SetIconResource($winpe, $data, file_get_contents("nostropia.ico"));
$result = $winpe->SavePEResourcesDirectory($data);

file_put_contents("origIcon.ico", $result["data"]);

// Write out the modified executable.

function patchPEString(&$peData, $originalServerIp, $newServerip)
{
    $serverIpOffset = strpos($peData, $originalServerIp . "\00");
    if ($serverIpOffset === false) {
        writeLog("Error", "Unable to locate offset of PE-String while patching.");
        exit;
    }
    $newServerIpLength = strlen($newServerip);
    $peData[$serverIpOffset - 4] = chr($newServerIpLength);
    for ($i = 0; $i < $newServerIpLength; $i++) {
        $peData[$serverIpOffset + $i] = $newServerip[$i];
    }
    $peData[$serverIpOffset + $newServerIpLength] = "\00"; //terminate with null
    writeLog("Info", "Patched PE-String at \"0x" . dechex($serverIpOffset) . "\".");
}

writeLog("Info", "Patching server ip.");
//current entwell server ip as of 23.01.2022 19:30
patchPEString($data, "79.110.84.75", "5.249.160.123");
writeLog("Info", "Patching server argument.");
patchPEString($data, "EntwellNostaleClient", "nostropia");


writeLog("Info", "Building Codecave assembly");

//entry point addr
$imageBaseAddr = $winpe->pe_opt_header["image_base"];
writeLog("Info", "Image Base 0x" . dechex($imageBaseAddr) . ".");
$codeBaseAddr = $imageBaseAddr + $winpe->pe_opt_header["code_base"];
writeLog("Info", "CODE Base 0x" . dechex($codeBaseAddr) . ".");
$entryPointAddr = $winpe->pe_opt_header["entry_point_addr"];
writeLog("Info", "EIP At Entry 0x" . dechex($entryPointAddr) . ".");

//returnpointer
function buildLoadLibraryShellcode($imageBase, $returnPointer, $pointerToDllPath, $loadLibraryPtr)
{
    $output = "\x68" . pack("V", $imageBase + $returnPointer) . "\x9c\x60\x68" . pack("V", $pointerToDllPath) . "\xb8" .
        pack("V", $loadLibraryPtr) .
        "\xff\xd0\x61\x9d\xc3";
    return $output;
}

$compiledAssembly = buildLoadLibraryShellcode($imageBaseAddr, $entryPointAddr, 0xdeadbeef, 0x8a637425 /* Load Library Thrunk function pointer */);

writeLog("Info", "Writing assembly to PE File.");

//$libraryName = "nostropia.dll\00";
//$section = $winpe->CreateNewPESection($data, ".nostropia", 0, WinPEFile::IMAGE_SCN_MEM_EXECUTE | WinPEFile::IMAGE_SCN_MEM_READ);

//$result = $winpe->ExpandLastPESection($data, strlen($compiledAssembly) + strlen($libraryName));
//$compiledAssembly = $libraryName;
//$compiledAssembly .= buildLoadLibraryShellcode($imageBaseAddr, $entryPointAddr, $imageBaseAddr + $section['info']['rva'], 0x407c80 /* Load Library Thrunk function pointer */);

//writeLog("Info", "Compiled assembly \"" . unpack('H*', $compiledAssembly)[1] . "\".");

//if ($result['success'] !== true) {
//    writeLog("Info", "Unable to add assembly to pe section.");
//    exit();
//}

//writeLog("Info", "Writing assembly to PE File at 0x" . dechex($result['pos']) . ".");
//$winpe->pe_opt_header['entry_point_addr'] = $section['info']['rva'] + strlen($libraryName);
//writeLog("Info", "Patching entry point to load our dll at 0x" . dechex($winpe->pe_opt_header["entry_point_addr"]) . ".");
//copy over compiled assembly to position
//for ($i = 0; $i < strlen($compiledAssembly); $i++) {
//    $data[$result['pos'] + $i] = $compiledAssembly[$i];
//}

$winpe->SaveHeaders($data);

$winpe->UpdateChecksum($data);

writeLog("Info", "Writing output PE File \"NostropiaClientX.exe\".");
file_put_contents("NostropiaClientX.exe", $data);
