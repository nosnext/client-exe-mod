# NosTropia ClientX Patcher

```php composer.phar install```

```php patchexe.php```

This tool patches origNostaleClientX.exe. It patches serverip & command line argument for startup, it also creates a new exe entrypoint that loads our clientmod nostropia.dll at startup and then resumes execution. 