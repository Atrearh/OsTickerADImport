<?php

// --- Необхідні класи osTicket ---
use PluginConfig;
use ConfigField;
use SimpleForm;
use SectionBreakField;
use TextboxField;
use TextareaField;
use PasswordField;
use BooleanField;
use ChoiceField;
use User;
use Organization;
use Staff;
use Signal;
use Messages;
use Http;
use Cfg;
use Format;
use Validator;
use PluginManager;
use Misc;

// Переконайтесь, що функція __() для перекладу доступна
if (!function_exists('__')) { function __($t, $d = null) { return $t; } }
// Переконайтесь, що функція osticket_url() доступна
if (!function_exists('osticket_url')) { function osticket_url($p, $q = null) { $u = ROOT_PATH.'scp/'.$p; if($q)$u.='?'.http_build_query($q); return $u; } }
// Перевірка констант
if (!defined('ROOT_PATH')) { define('ROOT_PATH', '../../'); }
if (!defined('INCLUDE_DIR')) { define('INCLUDE_DIR', ROOT_PATH . 'include/'); }
define('AD_IMPORT_PLUGIN_VERSION', '1.1');

// Використовуємо глобальний клас Plugin
class AdUserImportPlugin extends Plugin {
    var $config_class = 'AdUserImportPluginConfig';

    function getAjaxUrls($instance_id = null) {
        $plugin_id = $this->getId();
        $id = $instance_id ?: $plugin_id;
        if (!$id) {
            $this->log(1, 'Cannot get plugin/instance ID for AJAX URLs.');
            return [];
        }
        return [
            'base' => 'ajax.php/config/plugins/' . $id,
            'test-connection' => '/test-connection',
            'import-now' => '/import-now',
        ];
    }

    function handleAjax($action, $payload = null) {
        global $ost, $thisstaff;
        $this->log(4, "handleAjax called with action: " . $action);

        if (!$thisstaff || !$thisstaff->isAdmin()) {
            $this->log(2, "handleAjax: Permission denied for staff ID " . ($thisstaff ? $thisstaff->getId() : 'None'));
            Http::response(403, 'Permission Denied');
            return false;
        }

        $configInstance = $this->getConfig();
        if (!$configInstance instanceof AdUserImportPluginConfig) {
            $this->log(1, "handleAjax: Plugin configuration not loaded");
            Http::response(500, 'Plugin configuration not loaded');
            return false;
        }

        $response = null;
        switch ($action) {
            case 'test-connection':
                $response = $configInstance->ajaxTestConnection($payload ?: $_POST);
                break;
            case 'import-now':
                $response = $configInstance->ajaxImportUsers();
                break;
            default:
                $this->log(2, "handleAjax: Unknown action '{$action}'");
                Http::response(400, 'Unknown action');
                return false;
        }

        if (is_array($response)) {
            Http::json_response($response);
            return true;
        }
        Http::response(500, 'AJAX handler failed to return valid response');
        return false;
    }

    function bootstrap() {
        $this->log(4, "Bootstrapping AD Import Plugin v" . AD_IMPORT_PLUGIN_VERSION);
        Signal::connect('apps.scp', [$this, 'onStaffApps']);

        $ajax_urls = $this->getAjaxUrls();
        $base_url_path = parse_url($ajax_urls['base'], PHP_URL_PATH);

        if ($base_url_path) {
            // Получаем текущий URL из переменных сервера
            $current_url = '';
            $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https://' : 'http://';
            $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
            $request_uri = $_SERVER['REQUEST_URI'] ?? '';
            $current_url = $scheme . $host . $request_uri;

            if (defined('AJAX_REQUEST') && strpos($current_url, $base_url_path) !== false) {
                $this->log(4, "AJAX request detected for plugin URL: " . $current_url);
                $current_path = parse_url($current_url, PHP_URL_PATH);
                $action_path = substr($current_path, strlen($base_url_path));
                $action_key = array_search($action_path, $ajax_urls);

                if ($action_key && $action_key !== 'base') {
                    $this->log(4, "Attempting to handle AJAX action: " . $action_key);
                    if ($this->handleAjax($action_key, $_POST ?: $_GET)) {
                        exit;
                    } else {
                        exit;
                    }
                } else {
                    $this->log(2, "AJAX request detected but action path '{$action_path}' not recognized.");
                }
            }
        } else {
            $this->log(2, "Could not determine base AJAX URL path.");
        }
    }

    function onStaffApps(&$apps) {
        $plugin_id = $this->getId();
        if (!$plugin_id) return;
        $settings_url = osticket_url('plugins.php', ['id' => $plugin_id]);
        $apps['ad-user-import'] = [
            'title' => __('AD User Import'),
            'href' => $settings_url,
            'icon' => 'icon-user'
        ];
    }

    public static function runPeriodicImport() {
        error_log('[AD Import Plugin] runPeriodicImport static method called.');
        if (class_exists('Plugin')) {
            $instance = Plugin::lookup('user-import');
            if ($instance) {
                $instance->log(4, 'runPeriodicImport static method called.');
            }else {
                error_log('[AD Import Plugin] ERROR: Could not lookup plugin instance for periodic import.');
            }
        }else {
        error_log('[AD Import Plugin] ERROR: Plugin class not found.');
        }

        global $ost;
        if (php_sapi_name() != 'cli' && !defined('CRON_CLI')) {
            error_log('[AD Import Plugin] ERROR: Attempted to run periodic import outside of CLI/Cron.');
            return;
        }

        $instance = Plugin::lookup('user-import');
        if (!$instance) {
            error_log('[AD Import Plugin] ERROR: Could not lookup plugin instance for periodic import.');
            return;
        }

        $config = $instance->getConfig();
        if (!$config instanceof AdUserImportPluginConfig) {
            error_log('[AD Import Plugin] ERROR: Failed to get plugin config for periodic import.');
            $instance->log(1, 'Failed to get plugin config for periodic import.');
            return;
        }
        error_log('[AD Import Plugin] INFO: Running periodic import via cron.');
        $instance->log(3, 'Running periodic import via cron.');
        $config->importUsers(true);
    }

    function log($level, $message) {
        global $ost;
        $level_str = ($level == 1) ? 'ERROR' : (($level == 2) ? 'WARN' : (($level == 4) ? 'DEBUG' : 'INFO'));

        // Пробуем использовать системное логирование osTicket через глобальный объект $ost
        if (isset($ost) && is_object($ost) && method_exists($ost, 'log')) {
            // Метод $ost->log() принимает уровень, сообщение и источник
            $ost->log($level_str, $message, 'AD Import Plugin v' . AD_IMPORT_PLUGIN_VERSION);
        } elseif (class_exists('SystemLog')) {
            // Альтернатива для старых версий: используем SystemLog
            try {
                SystemLog::create([
                    'title' => 'AD Import Plugin v' . AD_IMPORT_PLUGIN_VERSION,
                    'log_type' => $level_str,
                    'log' => $message,
                    'date' => date('Y-m-d H:i:s'),
                    'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'
                ])->save();
            } catch (Exception $e) {
                // Если не удалось записать в SystemLog, используем error_log
                error_log('[AD Import Plugin] Failed to log to SystemLog: ' . $e->getMessage());
            }
        }

        // Всегда записываем в error_log для надежности
        error_log('[AD Import Plugin] ' . $level_str . ': ' . $message);
    }
}

class AdUserImportPluginConfig extends PluginConfig {

    private function log($level, $message) {
        if (is_object($this->plugin) && method_exists($this->plugin, 'log')) {
            $this->plugin->log($level, $message);
        } else {
            $level_str = ($level == 1) ? 'ERROR' : (($level == 2) ? 'WARN' : (($level == 4) ? 'DEBUG' : 'INFO'));
            error_log('[AD Import Plugin Config] ' . $level_str . ': ' . $message);
        }
    }

    function getOptions() {
        $this->log(4, "getOptions called.");
        $max_length = 255;
        $size = 60;

        $user_fields = ['' => __('— Do Not Map —')];
        if (class_exists('UserForm')) {
            try {
                $form = UserForm::getUserForm()->getForm();
                if ($form) { 
                    foreach ($form->getFields() as $field) { 
                        if ($field->isVisibleToUsers() && $field->isEditableToUsers()) { 
                            $fieldName = $field->get('name') ?: $field->get('label'); 
                            if ($fieldName) $user_fields[$fieldName] = $field->get('label'); 
                        } 
                    } 
                }
                if (!array_key_exists('name', $user_fields)) $user_fields['name'] = __('Name'); 
                if (!array_key_exists('email', $user_fields)) $user_fields['email'] = __('Email'); 
                if (!array_key_exists('phone', $user_fields)) $user_fields['phone'] = __('Phone Number');
            } catch (Exception $e) { 
                $this->log(2, 'Error getting user form fields: ' . $e->getMessage()); 
                $user_fields = ['' => __('— Do Not Map —'), 'name' => __('Name'), 'email' => __('Email'), 'phone' => __('Phone Number')]; 
            }
        } else { 
            $user_fields = ['' => __('— Do Not Map —'), 'name' => __('Name'), 'email' => __('Email'), 'phone' => __('Phone Number')]; 
        }

        $test_button_html = '<button type="button" id="test-ldap-connection" class="button">' . __('Test Connection') . '</button> <span id="test-ldap-result" style="display:none;"></span>';
        $import_button_html = '<button type="button" id="run-import-now" class="button button-primary">' . __('Run Import Now') . '</button> <span id="import-status" style="display:none;"></span>';

        // Откладываем генерацию JavaScript до полной инициализации плагина
        $test_button_js = '';
        $import_button_js = '';
        if (is_object($this->plugin) && method_exists($this->plugin, 'getAjaxUrls')) {
            $test_button_js = $this->getTestConnectionJs();
            $import_button_js = $this->getImportNowJs();
        } else {
            $this->log(4, "getOptions: Plugin object or getAjaxUrls method not available yet. JavaScript for buttons will be added dynamically.");
            // Добавляем JavaScript, который попытается загрузить URL позже
            $test_button_js = $this->getDeferredJs('test-ldap-connection', 'test-connection');
            $import_button_js = $this->getDeferredJs('run-import-now', 'import-now');
        }

        return [
            'ldap_connection_header' => new SectionBreakField([
                'title' => __('LDAP Connection Settings'),
                'hint' => __('Configure connection details for your Active Directory server.'),
                'after' => $test_button_html . $test_button_js,
            ]),
            'ldap_host' => new TextboxField([ 'label' => __('LDAP Host(s)'), 'configuration' => ['size' => $size, 'length' => $max_length], 'hint' => __('Enter LDAP server hostname or IP address. For high availability, list multiple hosts separated by space (e.g., "dc01.example.local dc02.example.local").'), 'required' => true, 'validators' => function($value) { if (empty(trim($value))) return __('LDAP Host is required'); } ]),
            'ldap_port' => new TextboxField([ 'label' => __('Port'), 'default' => '389', 'configuration' => ['size' => 10, 'length' => 5], 'hint' => __('Standard LDAP port is 389, LDAPS is 636.'), 'required' => true, 'validators' => function($value) { if (!is_numeric($value) || $value < 1 || $value > 65535) return __('Invalid port number (1-65535)'); } ]),
            'ldap_tls' => new BooleanField([ 'label' => __('Use StartTLS'), 'default' => false, 'configuration' => ['desc' => __('Use StartTLS for secure connection (typically on port 389). Uncheck for standard LDAP or LDAPS (port 636).')] ]),
            'ldap_ldaps' => new BooleanField([ 'label' => __('Use LDAPS'), 'default' => false, 'configuration' => ['desc' => __('Connect using LDAPS (SSL encryption, typically on port 636). Overrides StartTLS if checked.')] ]),
            'ldap_bind_dn' => new TextboxField([ 'label' => __('Bind DN'), 'configuration' => ['size' => $size, 'length' => $max_length], 'hint' => __('DN for the service account to bind to LDAP (e.g., CN=Service,OU=Users,DC=...) or UPN (service@example.local). Leave blank for anonymous bind (if allowed).'), 'required' => false ]),
            'ldap_password' => new PasswordField([ 'label' => __('Password'), 'configuration' => ['size' => $size, 'length' => $max_length], 'hint' => __('Password for the Bind DN.'), 'required' => false ]),

            'ldap_search_header' => new SectionBreakField([ 'title' => __('LDAP Search Configuration'), ]),
            'ldap_base_dn' => new TextareaField([ 'label' => __('Search Base DN(s)'), 'configuration' => ['rows' => 3, 'cols' => $size], 'hint' => __('Enter one or more Base DNs to search for users, one per line (e.g., OU=Users,DC=example,DC=local). The search will be performed in each specified DN.'), 'required' => true, 'validators' => function($value) { if (empty(trim($value))) return __('At least one Search Base DN is required'); } ]),
            'ldap_filter' => new TextboxField([ 'label' => __('LDAP Filter'), 'default' => '(&(objectClass=user)(objectCategory=person)(mail=*)(|(userAccountControl=512)(userAccountControl=66048)))', 'configuration' => ['size' => $size, 'length' => $max_length], 'hint' => __('LDAP filter to find user accounts (e.g., (&(objectClass=user)(memberOf=CN=Group,OU=Groups,...))). Default finds enabled users with email.'), 'required' => true ]),

            'ldap_mapping_header' => new SectionBreakField([ 'title' => __('Attribute Mapping'), 'hint' => __('Map LDAP attributes to osTicket user fields.') ]),
            'ldap_attr_email' => new TextboxField([ 'label' => __('Email Attribute'), 'default' => 'mail', 'configuration' => ['size' => 30, 'length' => 50], 'hint' => __('LDAP attribute for user\'s email address (required).'), 'required' => true ]),
            'ldap_attr_name' => new TextboxField([ 'label' => __('Full Name Attribute'), 'default' => 'displayName', 'configuration' => ['size' => 30, 'length' => 50], 'hint' => __('LDAP attribute for user\'s full name (e.g., displayName, cn). Required.'), 'required' => true ]),
            'ldap_map_phone' => new ChoiceField([ 'label' => __('Map Phone Number To'), 'hint' => __('Select osTicket field for LDAP phone attribute.'), 'choices' => $user_fields, 'default' => '' ]),
            'ldap_attr_phone' => new TextboxField([ 'label' => __('LDAP Phone Attribute'), 'default' => 'telephoneNumber', 'configuration' => ['size' => 30, 'length' => 50], 'hint' => __('LDAP attribute for phone number (e.g., telephoneNumber, mobile).') ]),
            'ldap_map_dept' => new ChoiceField([ 'label' => __('Map Department To'), 'hint' => __('Select osTicket field for LDAP department attribute (requires custom field or specific handling).'), 'choices' => $user_fields, 'default' => '' ]),
            'ldap_attr_dept' => new TextboxField([ 'label' => __('LDAP Department Attribute'), 'default' => 'department', 'configuration' => ['size' => 30, 'length' => 50], 'hint' => __('LDAP attribute for department.') ]),

            'import_settings_header' => new SectionBreakField([
                'title' => __('Import Options'),
                'after' => $import_button_html . $import_button_js,
            ]),
            'import_org' => new BooleanField([ 'label' => __('Assign to Default Organization'), 'default' => false, 'configuration' => ['desc' => __('Assign imported users to the default organization set in osTicket Admin Panel -> Settings -> Users.')] ]),
            'import_update' => new BooleanField([ 'label' => __('Update Existing Users'), 'default' => true, 'configuration' => ['desc' => __('Update name and mapped fields for existing users found by email.')] ]),
            'import_log_level' => new ChoiceField([ 'label' => __('Logging Level'), 'choices' => [ 0 => __('Errors Only'), 1 => __('Errors and Summary'), 2 => __('Detailed (Log each user)') ], 'default' => 1, 'hint' => __('Control the amount of information logged during import.') ]),
        ];
    }

    private function getDeferredJs($buttonId, $action) {
        // Этот метод генерирует JavaScript, который будет пытаться получить URL через AJAX
        $pluginId = $this->plugin ? $this->plugin->getId() : 'user-import';
        return <<<JS
        <script type="text/javascript">
        jQuery(document).ready(function($) {
            var button = $('#{$buttonId}');
            if (button.length) {
                button.prop('disabled', true).attr('title', 'Loading URL...');
                $.ajax({
                    url: 'ajax.php/config/plugins/{$pluginId}/get-urls',
                    type: 'GET',
                    dataType: 'json',
                    success: function(response) {
                        if (response && response.urls && response.urls['{$action}']) {
                            var url = response.urls['base'] + response.urls['{$action}'];
                            console.log('AD Import: Loaded URL for {$action}: ' + url);
                            button.prop('disabled', false).attr('title', '');
                            if ('{$action}' === 'test-connection') {
                                button.on('click', function(e) {
                                    e.preventDefault();
                                    var \$button = $(this); var \$resultSpan = $('#test-ldap-result');
                                    $resultSpan.text('Testing...').css('color', 'orange').show();
                                    \$button.prop('disabled', true);
                                    var formData = {'__CSRFToken__': window.ost && window.ost.CSRFToken || $('input[name=__CSRFToken__]').val() || $('meta[name=csrf-token]').attr('content') || '', 'ldap_host': $('input[name=ldap_host]').val(), 'ldap_port': $('input[name=ldap_port]').val(), 'ldap_tls': $('input[name=ldap_tls]').is(':checked') ? 1 : 0, 'ldap_ldaps': $('input[name=ldap_ldaps]').is(':checked') ? 1 : 0, 'ldap_bind_dn': $('input[name=ldap_bind_dn]').val(), 'ldap_password': $('input[name=ldap_password]').val() };
                                    console.log('AD Import: Testing connection with data:', formData);
                                    $.ajax({ url: url, type: 'POST', data: formData, dataType: 'json',
                                        success: function(r) { console.log('AD Import: Test response:', r); if (r && r.success) \$resultSpan.text(r.message||'OK').css('color','green'); else \$resultSpan.text('Error: '+(r.message||'?')).css('color','red'); },
                                        error: function(x,s,e) { console.error("AD Import AJAX Error:",s,e,x.status,x.responseText); var m='Error: AJAX failed.'; if(x.status===404)m+=' URL not found ('+url+'). Check AJAX setup.'; else if(x.status===403)m+=' Forbidden/CSRF invalid.'; else if(x.status===500)m+=' Server Error.'; else if(x.responseText)m+=' Response: '+x.responseText.substring(0,100); \$resultSpan.text(m).css('color','red'); },
                                        complete: function() { \$button.prop('disabled', false); }
                                    });
                                });
                            } else if ('{$action}' === 'import-now') {
                                button.on('click', function(e) {
                                    e.preventDefault();
                                    var \$button = $(this); var \$statusSpan = $('#import-status');
                                    if (!confirm(__('Are you sure you want to start the manual import now?'))) return;
                                    $statusSpan.text(__('Importing... Please wait.')).css('color', 'orange').show();
                                    \$button.prop('disabled', true);
                                    var postData = { '__CSRFToken__': window.ost && window.ost.CSRFToken || $('input[name=__CSRFToken__]').val() || $('meta[name=csrf-token]').attr('content') || '' };
                                    console.log('AD Import: Running import via AJAX:', postData);
                                    $.ajax({ url: url, type: 'POST', data: postData, dataType: 'json',
                                        success: function(r) { console.log('AD Import: Import response:', r); if (r && r.success) \$statusSpan.text(r.message||'OK').css('color','green'); else \$statusSpan.text(__('Error:')+' '+(r.message||'Failed')).css('color','red'); },
                                        error: function(x,s,e) { console.error("AD Import AJAX Error:",s,e,x.status,x.responseText); var m=__('Error: AJAX failed.'); if(x.status===404)m+=' '+__('URL not found ('+url+'). Check AJAX setup.'); else if(x.status===403)m+=' '+__('Forbidden/CSRF invalid.'); else if(x.status===500)m+=' '+__('Server Error.'); else if(x.responseText)m+=' '+__('Response:')+' '+x.responseText.substring(0,100); \$statusSpan.text(m).css('color','red'); },
                                        complete: function() { \$button.prop('disabled', false); }
                                    });
                                });
                            }
                        } else {
                            console.warn('AD Import: Failed to load URL for {$action}.');
                            button.prop('disabled', true).attr('title', 'Failed to load AJAX URL');
                        }
                    },
                    error: function(xhr, status, error) {
                        console.error('AD Import: Failed to fetch AJAX URLs:', status, error);
                        button.prop('disabled', true).attr('title', 'Failed to load AJAX URL');
                    }
                });
            } else {
                console.warn('AD Import: Button #{$buttonId} not found.');
            }
        });
        </script>
JS;
    }

    private function getTestConnectionJs() {
        if (!is_object($this->plugin) || !method_exists($this->plugin, 'getAjaxUrls')) return '';
        $urls = $this->plugin->getAjaxUrls();
        if (!isset($urls['base']) || !isset($urls['test-connection'])) return '';
        $url = $urls['base'] . $urls['test-connection'];

        $csrf_token_js = 'window.ost && window.ost.CSRFToken || $(\'input[name=__CSRFToken__]\').val() || $(\'meta[name=csrf-token]\').attr(\'content\') || \'\'';
        $this->log(4, "Generating JS for Test Connection button, URL: " . $url);

        return <<<JS
        <script type="text/javascript">
        jQuery(document).ready(function($) {
            var testButton = $('#test-ldap-connection');
            if (testButton.length) {
                if (!'{$url}') {
                    console.warn('AD Import: Test Connection URL is empty, disabling button.');
                    testButton.prop('disabled', true).attr('title', 'AJAX URL not configured');
                    return;
                }
                testButton.on('click', function(e) {
                    e.preventDefault();
                    var \$button = $(this); var \$resultSpan = $('#test-ldap-result');
                    $resultSpan.text('Testing...').css('color', 'orange').show();
                    \$button.prop('disabled', true);
                    var formData = {'__CSRFToken__': {$csrf_token_js}, 'ldap_host': $('input[name=ldap_host]').val(), 'ldap_port': $('input[name=ldap_port]').val(), 'ldap_tls': $('input[name=ldap_tls]').is(':checked') ? 1 : 0, 'ldap_ldaps': $('input[name=ldap_ldaps]').is(':checked') ? 1 : 0, 'ldap_bind_dn': $('input[name=ldap_bind_dn]').val(), 'ldap_password': $('input[name=ldap_password]').val() };
                    console.log('AD Import: Testing connection with data:', formData);
                    $.ajax({ url: '{$url}', type: 'POST', data: formData, dataType: 'json',
                        success: function(r) { console.log('AD Import: Test response:', r); if (r && r.success) \$resultSpan.text(r.message||'OK').css('color','green'); else \$resultSpan.text('Error: '+(r.message||'?')).css('color','red'); },
                        error: function(x,s,e) { console.error("AD Import AJAX Error:",s,e,x.status,x.responseText); var m='Error: AJAX failed.'; if(x.status===404)m+=' URL not found ({$url}). Check AJAX setup.'; else if(x.status===403)m+=' Forbidden/CSRF invalid.'; else if(x.status===500)m+=' Server Error.'; else if(x.responseText)m+=' Response: '+x.responseText.substring(0,100); \$resultSpan.text(m).css('color','red'); },
                        complete: function() { \$button.prop('disabled', false); }
                    });
                });
            } else {
                console.warn('AD Import: Test Connection button (#test-ldap-connection) not found.');
            }
        });
        </script>
JS;
    }

    private function getImportNowJs() {
        if (!is_object($this->plugin) || !method_exists($this->plugin, 'getAjaxUrls')) return '';
        $urls = $this->plugin->getAjaxUrls();
        if (!isset($urls['base']) || !isset($urls['import-now'])) return '';
        $url = $urls['base'] . $urls['import-now'];

        $csrf_token_js = 'window.ost && window.ost.CSRFToken || $(\'input[name=__CSRFToken__]\').val() || $(\'meta[name=csrf-token]\').attr(\'content\') || \'\'';
        $this->log(4, "Generating JS for Import Now button, URL: " . $url);

        return <<<JS
        <script type="text/javascript">
        jQuery(document).ready(function($) {
            var importButton = $('#run-import-now');
            if (importButton.length) {
                if (!'{$url}') {
                    console.warn('AD Import: Import Now URL is empty, disabling button.');
                    importButton.prop('disabled', true).attr('title', 'AJAX URL not configured');
                    return;
                }
                importButton.on('click', function(e) {
                    e.preventDefault();
                    var \$button = $(this); var \$statusSpan = $('#import-status');
                    if (!confirm(__('Are you sure you want to start the manual import now?'))) return;
                    $statusSpan.text(__('Importing... Please wait.')).css('color', 'orange').show();
                    \$button.prop('disabled', true);
                    var postData = { '__CSRFToken__': {$csrf_token_js} };
                    console.log('AD Import: Running import via AJAX:', postData);
                    $.ajax({ url: '{$url}', type: 'POST', data: postData, dataType: 'json',
                        success: function(r) { console.log('AD Import: Import response:', r); if (r && r.success) \$statusSpan.text(r.message||'OK').css('color','green'); else \$statusSpan.text(__('Error:')+' '+(r.message||'Failed')).css('color','red'); },
                        error: function(x,s,e) { console.error("AD Import AJAX Error:",s,e,x.status,x.responseText); var m=__('Error: AJAX failed.'); if(x.status===404)m+=' '+__('URL not found ({$url}). Check AJAX setup.'); else if(x.status===403)m+=' '+__('Forbidden/CSRF invalid.'); else if(x.status===500)m+=' '+__('Server Error.'); else if(x.responseText)m+=' '+__('Response:')+' '+x.responseText.substring(0,100); \$statusSpan.text(m).css('color','red'); },
                        complete: function() { \$button.prop('disabled', false); }
                    });
                });
            } else {
                console.warn('AD Import: Import Now button (#run-import-now) not found.');
            }
        });
        </script>
JS;
    }

    function ajaxTestConnection($data) {
        $this->log(4, "ajaxTestConnection called with data: " . print_r($data, true));
        $host = $data['ldap_host'] ?? '';
        $port = filter_var($data['ldap_port'] ?? 389, FILTER_VALIDATE_INT) ?: 389;
        $use_tls = !empty($data['ldap_tls']); 
        $use_ldaps = !empty($data['ldap_ldaps']);
        $bind_dn = $data['ldap_bind_dn'] ?? null; 
        $password = $data['ldap_password'] ?? null;
        $response = ['success' => false, 'message' => ''];

        if (empty($host)) { 
            $response['message'] = __('LDAP Host is required.'); 
            return $response; 
        }
        if ($use_tls && $use_ldaps) { 
            $response['message'] = __('Cannot use both StartTLS and LDAPS.'); 
            return $response; 
        }

        $ldap_uri = $this->buildLdapUri($host, $port, $use_tls, $use_ldaps);
        $timeout = 5; 
        putenv('LDAPTIMELIMIT=' . $timeout); 
        $ldap = @ldap_connect($ldap_uri, $port); 
        putenv('LDAPTIMELIMIT');

        if (!$ldap) { 
            $response['message'] = sprintf(__('Failed to connect... (%s:%d).'), $ldap_uri, $port); 
            return $response; 
        }

        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3); 
        ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0); 
        ldap_set_option($ldap, LDAP_OPT_NETWORK_TIMEOUT, $timeout);

        $tls_started = false;
        if ($use_tls && !$use_ldaps) { 
            if (!@ldap_start_tls($ldap)) { 
                $response['message'] = __('Failed to start TLS:') . ' ' . ldap_error($ldap); 
                ldap_unbind($ldap); 
                return $response; 
            } 
            $tls_started = true; 
        }

        $bind_success = false; 
        $bind_error = '';
        if (!empty($bind_dn) && isset($password)) { 
            if (@ldap_bind($ldap, $bind_dn, $password)) {
                $bind_success = true; 
            } else { 
                $bind_error = ldap_error($ldap); 
                $response['message'] = sprintf(__('Bind failed for DN "%s". Error: %s'), $bind_dn, $bind_error); 
            }
        } elseif (empty($bind_dn)) { 
            if (@ldap_bind($ldap)) {
                $bind_success = true; 
            } else { 
                $bind_error = ldap_error($ldap); 
                $response['message'] =sprintf(__('Anonymous bind failed. Error: %s'), $bind_error); 
            }
        } else { 
            $response['message'] = __('Password is required for the specified Bind DN.'); 
        }

        ldap_unbind($ldap);
        if ($bind_success) { 
            $response['success'] = true; 
            $conn_type = $use_ldaps ? 'LDAPS' : ($tls_started ? 'TLS' : 'Unencrypted'); 
            $bind_type = empty($bind_dn) ? 'Anonymous Bind' : sprintf('Bind as %s', $bind_dn); 
            $response['message'] = sprintf(__('Connection successful! (%s, %s)'), $conn_type, $bind_type); 
        }
        return $response;
    }

    function ajaxImportUsers() {
        $this->log(4, "ajaxImportUsers called. Starting user import process.");
        $result = $this->importUsers(false);
        $this->log(4, "ajaxImportUsers completed with result: " . print_r($result, true));
        return $result;
    }

    function importUsers($is_cron = false) {
    $this->log(3, "Import process " . ($is_cron ? "started (cron)" : "started (manual/ajax)"));

    $config = $this->getConfig();
    $log_level = $config['import_log_level'] ?? 1;

    $safe_config = $config->getInfo();
    unset($safe_config['ldap_password']);
    if ($log_level >= 2) $this->log(4, "Import using config: " . print_r($safe_config, true));

    if (empty($config['ldap_host']) || empty($config['ldap_port']) || empty($config['ldap_base_dn']) || empty($config['ldap_filter']) || empty($config['ldap_attr_email']) || empty($config['ldap_attr_name'])) {
        $error_msg = 'Import failed: Missing required configuration.';
        $this->log(1, $error_msg);
        if (!$is_cron) Messages::error(__('Import Failed: Missing required configuration...'));
        return ['success' => false, 'message' => $error_msg];
    }

    $imported_count = 0; 
    $updated_count = 0; 
    $skipped_count = 0; 
    $error_count = 0; 
    $total_entries = 0;

    $ldap_uri = $this->buildLdapUri($config['ldap_host'], $config['ldap_port'], $config['ldap_tls'], $config['ldap_ldaps']);
    $ldap_port = filter_var($config['ldap_port'] ?? 389, FILTER_VALIDATE_INT) ?: 389;
    $timeout = 10; 
    putenv('LDAPTIMELIMIT=' . $timeout); 
    $ldap = @ldap_connect($ldap_uri, $ldap_port); 
    putenv('LDAPTIMELIMIT');

    if (!$ldap) { 
        $error_msg = sprintf(__('Failed to connect... (%s:%d).'), $ldap_uri, $ldap_port); 
        $this->log(1, $error_msg); 
        if (!$is_cron) Messages::error($error_msg); 
        return ['success' => false, 'message' => $error_msg]; 
    }

    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3); 
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0); 
    ldap_set_option($ldap, LDAP_OPT_NETWORK_TIMEOUT, $timeout); 
    ldap_set_option($ldap, LDAP_OPT_TIMELIMIT, $timeout);

    $tls_started = false;
    if ($config['ldap_tls'] && !$config['ldap_ldaps']) { 
        if (!@ldap_start_tls($ldap)) { 
            $error_msg = __('Failed to start TLS:') . ' ' . ldap_error($ldap); 
            $this->log(1, $error_msg); 
            if (!$is_cron) Messages::error($error_msg); 
            ldap_unbind($ldap); 
            return ['success' => false, 'message' => $error_msg]; 
        } 
        $tls_started = true; 
        if ($log_level >= 1) $this->log(4, "StartTLS successful."); 
    }

    $bind_dn = $config['ldap_bind_dn'] ?? null; 
    $password = $config->get('ldap_password'); 
    $bind_success = false; 
    $bind_error = '';

    if (!empty($bind_dn) && isset($password)) { 
        if (@ldap_bind($ldap, $bind_dn, $password)) {
            $bind_success = true; 
        } else { 
            $bind_error = ldap_error($ldap); 
            $error_msg = sprintf(__('LDAP bind failed for DN "%s". Error: %s'), $bind_dn, $bind_error); 
        }
    } else { 
        if (@ldap_bind($ldap)) {
            $bind_success = true; 
        } else { 
            $bind_error = ldap_error($ldap); 
            $error_msg = sprintf(__('LDAP anonymous bind failed. Error: %s'), $bind_error); 
        }
    }

    if (!$bind_success) { 
        $this->log(1, $error_msg); 
        if (!$is_cron) Messages::error($error_msg); 
        ldap_unbind($ldap); 
        return ['success' => false, 'message' => $error_msg]; 
    }

    if ($log_level >= 1) $this->log(4, "LDAP Bind successful (" . (empty($bind_dn) ? "Anonymous" : $bind_dn) . ").");

    $attributes = array_filter([ 
        $config['ldap_attr_email'], 
        $config['ldap_attr_name'], 
        !empty($config['ldap_map_phone']) ? $config['ldap_attr_phone'] : null, 
        !empty($config['ldap_map_dept']) ? $config['ldap_attr_dept'] : null, 
        'dn' 
    ]);
    $attributes = array_unique(array_map('strtolower', $attributes));

    $base_dns = preg_split('/\r\n|\r|\n/', $config['ldap_base_dn']); 
    $base_dns = array_map('trim', array_filter($base_dns));

    if (empty($base_dns)) { 
        $error_msg = 'Import failed: No valid Search Base DN provided.'; 
        $this->log(1, $error_msg); 
        if (!$is_cron) Messages::error($error_msg); 
        ldap_unbind($ldap); 
        return ['success' => false, 'message' => $error_msg]; 
    }

    $all_entries = []; 
    $processed_dns = [];

    foreach ($base_dns as $base_dn) {
        if ($log_level >= 1) $this->log(4, "Searching LDAP in '{$base_dn}' with filter '{$config['ldap_filter']}'");
        $sizelimit = 0; 
        $search_result = @ldap_search($ldap, $base_dn, $config['ldap_filter'], $attributes, 0, $sizelimit, $timeout);

        if (!$search_result) { 
            $error_msg = sprintf(__("LDAP search failed in '%s'. Error: %s"), $base_dn, ldap_error($ldap)); 
            $this->log(2, $error_msg); 
            $error_count++; 
            continue; 
        }

        $entries = @ldap_get_entries($ldap, $search_result);
        if ($entries === false) { 
            $error_msg = sprintf(__("Failed to get entries... in '%s'. Error: %s"), $base_dn, ldap_error($ldap)); 
            $this->log(2, $error_msg); 
            $error_count++; 
            continue; 
        }

        if ($log_level >= 1) $this->log(4, "Found {$entries['count']} entries in '{$base_dn}'.");

        for ($i = 0; $i < $entries['count']; $i++) { 
            $dn = strtolower($entries[$i]['dn']); 
            if (!isset($processed_dns[$dn])) { 
                $all_entries[] = $entries[$i]; 
                $processed_dns[$dn] = true; 
            } 
        }

        @ldap_free_result($search_result);
    }

    ldap_unbind($ldap);
    $total_entries = count($all_entries);
    if ($log_level >= 1) $this->log(3, "Total unique entries found: " . $total_entries);

    // Добавляем проверку: если не найдено ни одного пользователя, логируем это
    if ($total_entries === 0) {
        $this->log(1, "No users found matching the LDAP filter '{$config['ldap_filter']}' in Base DN(s): " . implode(', ', $base_dns));
        return ['success' => false, 'message' => 'No users found matching the LDAP filter.'];
    }

    $default_org_id = null;
    if ($config['import_org']) { 
        $default_org = Organization::lookupByName(Cfg::get('default_organization_name')); 
        if ($default_org) { 
            $default_org_id = $default_org->getId(); 
            if ($log_level >= 1) $this->log(4, "Default org found: '{$default_org->getName()}' (ID: {$default_org_id})"); 
        } else { 
            if ($log_level >= 0) $this->log(2, "Warning: Default org '" . Cfg::get('default_organization_name') . "' not found."); 
            if (!$is_cron) Messages::warning(__('Default organization not found...')); 
        } 
    }

    foreach ($all_entries as $user_entry) {
        $errors = []; 
        $email_attr = $config['ldap_attr_email']; 
        $name_attr = $config['ldap_attr_name']; 
        $phone_attr = $config['ldap_attr_phone']; 
        $dept_attr = $config['ldap_attr_dept'];

        $email = $this->getLdapAttribute($user_entry, $email_attr); 
        $name = $this->getLdapAttribute($user_entry, $name_attr); 
        $user_dn = $user_entry['dn'];

        if (empty($email) || !Validator::is_email($email)) { 
            if ($log_level >= 1) $this->log(2, "Skipping (DN: {$user_dn}): Invalid email ('{$email}'). Attr: {$email_attr}"); 
            $skipped_count++; 
            continue; 
        }

        if (empty($name)) { 
            if ($log_level >= 1) $this->log(2, "Skipping (DN: {$user_dn}): Missing name. Attr: {$name_attr}"); 
            $skipped_count++; 
            continue; 
        }

        $phone = !empty($config['ldap_map_phone']) ? $this->getLdapAttribute($user_entry, $phone_attr) : null;
        $department_value = !empty($config['ldap_map_dept']) ? $this->getLdapAttribute($user_entry, $dept_attr) : null;

        $map_phone_to = $config['ldap_map_phone']; 
        $map_dept_to = $config['ldap_map_dept'];

        $existing_user = User::lookupByEmail($email);
        if ($existing_user) {
            if ($config['import_update']) {
                $form_data = []; 
                $changed = false; 
                $form = $existing_user->getForm();

                if ($existing_user->getName() != $name) { 
                    $form_data['name'] = $name; 
                    $changed = true; 
                }

                if ($phone !== null && !empty($map_phone_to)) { 
                    $current_phone = ''; 
                    if ($form && ($field = $form->getField($map_phone_to))) {
                        $current_phone = $field->getAnswer()->getValue(); 
                    } elseif (method_exists($existing_user, 'getPhoneNumber')) {
                        $current_phone = $existing_user->getPhoneNumber($map_phone_to); 
                    }
                    if ($current_phone != $phone) { 
                        $form_data[$map_phone_to] = $phone; 
                        $changed = true; 
                    } 
                }

                if ($department_value !== null && !empty($map_dept_to)) { 
                    $current_dept = ''; 
                    if ($form && ($field = $form->getField($map_dept_to))) {
                        $current_dept = $field->getAnswer()->getValue(); 
                    }
                    if ($current_dept != $department_value) { 
                        $form_data[$map_dept_to] = $department_value; 
                        $changed = true; 
                    } 
                }

                if ($default_org_id && !$existing_user->getOrgId()) { 
                    $form_data['org_id'] = $default_org_id; 
                    $changed = true; 
                }

                if ($changed && !empty($form_data)) {
                    if ($form && method_exists($form, 'isValidFor') && $form->isValidFor($existing_user, $form_data)) { 
                        if ($existing_user->update($form->getClean(), $errors)) { 
                            if ($log_level >= 2) $this->log(4, "Updated user: {$email} (DN: {$user_dn}). Changes: " . implode(', ', array_keys($form_data))); 
                            $updated_count++; 
                        } else { 
                            if ($log_level >= 0) $this->log(1, "Failed update (via form): {$email} (DN: {$user_dn}). Errors: " . print_r($errors, true)); 
                            $error_count++; 
                            $skipped_count++; 
                        } 
                    } elseif ($form) { 
                        if ($log_level >= 0) $this->log(2, "Failed update (form validation): {$email} (DN: {$user_dn}). Errors: " . print_r($form->errors(), true)); 
                        $error_count++; 
                        $skipped_count++; 
                    } else { 
                        if ($existing_user->update($form_data, $errors)) { 
                            if ($log_level >= 2) $this->log(4, "Updated user (direct): {$email} (DN: {$user_dn}). Changes: " . implode(', ', array_keys($form_data))); 
                            $updated_count++; 
                        } else { 
                            if ($log_level >= 0) $this->log(1, "Failed update (direct): {$email} (DN: {$user_dn}). Errors: " . print_r($errors, true)); 
                            $error_count++; 
                            $skipped_count++; 
                        } 
                    }
                } else { 
                    if ($log_level >= 2) $this->log(4, "Skipping update (no changes): {$email} (DN: {$user_dn})"); 
                    $skipped_count++; 
                }
            } else { 
                if ($log_level >= 2) $this->log(4, "Skipping update (disabled): {$email} (DN: {$user_dn})"); 
                $skipped_count++; 
            }
        } else {
            $user_data = ['name' => $name, 'email' => $email, 'status' => 0];
            if ($default_org_id) $user_data['org_id'] = $default_org_id;
            if ($phone !== null && !empty($map_phone_to)) $user_data[$map_phone_to] = $phone;
            if ($department_value !== null && !empty($map_dept_to)) $user_data[$map_dept_to] = $department_value;

            $new_user = User::create($user_data, $errors);
            if ($new_user instanceof User) { 
                if ($log_level >= 2) $this->log(4, "Imported new user: {$name} <{$email}> (DN: {$user_dn})" . ($default_org_id ? " to Org ID: {$default_org_id}" : "")); 
                $imported_count++; 
            } else { 
                if ($log_level >= 0) $this->log(1, "Failed create user: {$name} <{$email}> (DN: {$user_dn}). Errors: " . print_r($errors, true)); 
                $error_count++; 
                $skipped_count++; 
            }
        }
    }

    $summary_msg = sprintf(__('Import finished. Found: %d, Imported: %d, Updated: %d, Skipped: %d, Errors: %d.'), $total_entries, $imported_count, $updated_count, $skipped_count, $error_count);
    if ($log_level >= 1) $this->log(3, $summary_msg);
    if (!$is_cron) { 
        if ($error_count > 0) {
            Messages::warning($summary_msg . ' ' . __('Check system logs for details.')); 
        } else {
            Messages::success($summary_msg); 
        }
    }
    return ['success' => ($error_count == 0), 'message' => $summary_msg];
 }

    private function buildLdapUri($hosts, $port, $use_tls, $use_ldaps) {
        $hosts = trim($hosts); 
        if (empty($hosts)) return '';

        if ($use_ldaps) { 
            $protocol = 'ldaps://'; 
            $default_port = 636; 
        } else { 
            $protocol = 'ldap://'; 
            $default_port = 389; 
        }

        $host_list = preg_split('/\s+/', $hosts); 
        $uris = [];

        foreach ($host_list as $host) { 
            $host = trim($host); 
            if (empty($host)) continue; 
            if (strpos($host, '://') === false) {
                $uri = $protocol . $host; 
            } else {
                $uri = $host; 
            }
            if ($port != $default_port && parse_url($uri, PHP_URL_PORT) === null) {
                $uris[] = rtrim($uri,'/') . ':' . $port; 
            } else {
                $uris[] = rtrim($uri,'/'); 
            }
        }

        return implode(' ', $uris);
    }

    private function getLdapAttribute($entry, $attributeName) {
        $attributeName = strtolower(trim($attributeName)); 
        if (empty($attributeName)) return null;

        if (isset($entry[$attributeName][0])) { 
            if (in_array($attributeName, ['objectsid', 'objectguid']) && is_string($entry[$attributeName][0])) {
                return '[binary data]'; 
            }
            return $entry[$attributeName][0]; 
        }
        return null;
    }

    function pre_save(&$config, &$errors) {
        if ($config['ldap_tls'] && $config['ldap_ldaps']) { 
            $errors['ldap_ldaps'] = __('Cannot use both StartTLS and LDAPS simultaneously.'); 
            return false; 
        }
        if (!empty($config['ldap_map_phone']) && empty($config['ldap_attr_phone'])) { 
            $errors['ldap_attr_phone'] = __('LDAP Phone Attribute is required when mapping Phone Number.'); 
            return false; 
        }
        if (!empty($config['ldap_map_dept']) && empty($config['ldap_attr_dept'])) { 
            $errors['ldap_attr_dept'] = __('LDAP Department Attribute is required when mapping Department.'); 
            return false; 
        }
        $this->log(4, "pre_save validation passed.");
        return true;
    }
}