<?php
return [
    'id'          => 'user-import',
    'version'     => '1.0',
    'name'        => 'AD User Import',
    'author'      => 'SEM',
    'description' => 'Імпортує користувачів з Active Directory у osTicket.',
    'plugin'      => 'ADImport.php:AdUserImportPlugin',
];