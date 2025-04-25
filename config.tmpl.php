<?php return [
    'ldap_host'     => 'ldap://dc01.example.local',
    'ldap_port'     => '389',
    'ldap_bind_dn'  => 'CN=ldap_user,CN=Users,DC=example,DC=local',
    'ldap_password' => '',
    'ldap_base_dn'  => 'OU=Users,DC=example,DC=local',
    'ldap_filter'   => '(objectClass=user)',
];