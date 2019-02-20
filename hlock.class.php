<?php
/**
 * hlock class
 * PHP Version 7
 *
 * @see       https://github.com/Trebaxa/hlock
 *
 * @author    Harald Petrich <service@trebaxa.com>
 * @copyright 2018 - 2019 Harald Petrich
 * @license   http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 * @note      This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. This project should help us developer to protect our PHP projects from
 * hacking.
 * 
 * This version is compatible with keimeno CMS, but can easly changed to be compatible with Wordpress, Joomla Typo3.
 * Just change the path to files and ensure the HLOCK_ROOT is successfully set.
 * 
 * How to implement?
 * add in index.php:
 * require (CMS_ROOT . 'includes/hlock.class.php');
 * hlock::run();
 * 
 * In keimenbo CMS the hlock project is already implemented in the core.
 */

$dir = str_replace(DIRECTORY_SEPARATOR, '/', realpath(dirname(__FILE__)));
$dir = str_replace("/includes", "/", $dir);
define('HLOCK_ROOT', $dir);
define('HLOCK_HOST', str_replace('www.', '', $_SERVER['HTTP_HOST']));
date_default_timezone_set('Europe/Berlin');

class hlock {

    protected static $hpath = HLOCK_ROOT . 'cache/accesslog/';
    protected static $hlock_blocked_file = HLOCK_ROOT . 'includes/lib/hlock/hacklogblock_' . HLOCK_HOST . '.txt';
    protected static $hlock_blacklist = HLOCK_ROOT . 'includes/lib/hlock/blacklist.json';
    protected static $badips_file = HLOCK_ROOT . 'includes/lib/hlock/badips_' . HLOCK_HOST . '.txt';
    protected static $badbots_file = HLOCK_ROOT . 'includes/lib/hlock/badbots_' . HLOCK_HOST . '.txt';
    protected static $hcache_lifetime_hours = 3;
    protected static $blacklis_lifetime_hours = 1;
    protected static $log_lines_count = 98;
    protected static $email = '';

    /**
     * hlock::run()
     * 
     * @return void
     */
    public static function run() {
        if (!is_dir(HLOCK_ROOT . 'cache/accesslog'))
            mkdir(HLOCK_ROOT . 'cache/accesslog', 0755);

        if ($handle = opendir(static::$hpath)) {
            while (false !== ($file = readdir($handle))) {
                if ((integer)(time() - filemtime(static::$hpath . $file)) > (static::$hcache_lifetime_hours * 3600) && $file !== '.' && $file !== '..') {
                    @unlink(static::$hpath . $file);
                }
            }
        }

        $fname = (strstr($_SERVER['HTTP_USER_AGENT'], 'bot')) ? $_SERVER['HTTP_USER_AGENT'] : $_SERVER['HTTP_USER_AGENT'] . $_SERVER['REMOTE_ADDR'];
        $hfile = static::$hpath . md5($fname);
        $hcount = 0;
        if (is_file($hfile)) {
            $arr = explode(PHP_EOL, file_get_contents($hfile));
            $hcount = (int)$arr[0];
            $hcount++;
        }
        file_put_contents($hfile, implode(PHP_EOL, array(
            $hcount,
            $_SERVER['HTTP_USER_AGENT'],
            $_SERVER['REMOTE_ADDR'],
            date('Y-m-d H:i:s'),
            )));


        self::block_bad_bots();
        self::block_bad_ips();
        self::detect_injection();
        self::clear_blocked();
        self::block_ips_and_bots_from_blacklist();
        #self::check_agent();

        if (isset($_GET['hlock'])) {
            $arr = array();
            $result = self::read_logs();
            self::echo_table($result['hour_log'], $result['hour_log_count'] . ' Clients (last hour)');
            self::echo_table($result['blocked_bots'], 'Bad Bot blocked list');
            die();
        }
    }

    /**
     * hlock::block_ips_and_bots_from_blacklist()
     * 
     * @return void
     */
    private static function block_ips_and_bots_from_blacklist() {
        $user_agent = self::get_user_agent();
        $json = json_decode(self::get_black_list(), true);
        # checkj IPs
        foreach ((array )$json['ips'] as $row) {
            $hash = md5($_SERVER['REMOTE_ADDR'] . $user_agent);
            if ($row['b_iphash'] == $hash) {
                self::exit_env('BLACK_LIST_IP' . $hash);
            }
        }
        #check bots
        foreach ((array )$json['bots'] as $row) {
            $bot_key = trim(strtolower($row['b_bot']));
            if (!empty($bot_key) && strstr($user_agent, $bot_key)) {
                self::exit_env('BLACK_LIST_BOT');
            }
        }

    }

    /**
     * hlock::check_agent()
     * 
     * @return void
     */
    private static function check_agent() {
        # invalid USER AGENT
        $user_agent = self::get_user_agent();
        if (strlen($user_agent) < 2) {
            self::report_hack('invalid user agent');
            self::exit_env('USER_AGENT');
        }
    }

    /**
     * hlock::get_user_agent()
     * 
     * @return
     */
    public static function get_user_agent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 254) : '';
    }

    /**
     * hlock::read_logs()
     * 
     * @param mixed $k
     * @return void
     */
    public static function read_logs() {
        $k = 0;
        $result['hour_log'] = $result['blocked_bots'] = array();
        if ($handle = opendir(static::$hpath)) {
            while (false !== ($file = readdir($handle))) {
                if ($file !== '.' && $file !== '..') {
                    $result['hour_log'][] = explode(PHP_EOL, file_get_contents(static::$hpath . $file));
                }
                $k++;
            }
        }
        if (is_file(static::$hlock_blocked_file)) {
            $blocked = explode(PHP_EOL, file_get_contents(static::$hlock_blocked_file));
            foreach ($blocked as $key => $line) {
                $result['blocked_bots'][] = explode("\t", $line);
            }
        }
        $result['hour_log_count'] = $k;
        return $result;
    }

    /**
     * hlock::read_lines_from_file()
     * 
     * @param mixed $file
     * @param mixed $maxLines
     * @param bool $reverse
     * @return
     */
    protected static function read_lines_from_file($file, $maxLines, $reverse = false) {
        $lines = file($file);
        if ($reverse) {
            $lines = array_reverse($lines);
        }
        $tmpArr = array();
        if ($maxLines > count($lines)) {
            return false;
        }

        for ($i = 0; $i < $maxLines; $i++) {
            array_push($tmpArr, $lines[$i]);
        }
        if ($reverse) {
            $tmpArr = array_reverse($tmpArr);
        }
        $out = "";
        for ($i = 0; $i < $maxLines; $i++) {
            $out .= $tmpArr[$i] . PHP_EOL;
        }
        return $out;
    }

    /**
     * hlock::clear_blocked()
     * 
     * @return void
     */
    protected static function clear_blocked() {
        if (is_file(static::$hlock_blocked_file) && filesize(static::$hlock_blocked_file) > 6000) {
            $lines = self::read_lines_from_file(static::$hlock_blocked_file, static::$log_lines_count, true);
            if ($lines !== false && is_string($lines))
                file_put_contents(static::$hlock_blocked_file, $lines);
        }
    }

    /**
     * hlock::block_bad_bots()
     * 
     * @return void
     */
    protected static function block_bad_bots() {
        $badbots = self::get_bad_bots();
        if ($_SERVER['HTTP_USER_AGENT'] != str_ireplace($badbots, '*', $_SERVER['HTTP_USER_AGENT'])) {
            $fp = fopen(static::$hlock_blocked_file, 'a+');
            fwrite($fp, implode("\t", array(
                date('Y-m-d H:i:s'),
                $_SERVER['HTTP_USER_AGENT'],
                'AGENT',
                $_SERVER['REMOTE_ADDR'])) . PHP_EOL);
            fclose($fp);
            self::exit_env('BOT');
        }
    }

    /**
     * hlock::block()
     * 
     * @return void
     */
    protected static function exit_env($reason = "") {
        header('HTTP/1.0 403 Forbidden');
        die('Bad Agent [' . $reason . ']');
    }

    /**
     * hlock::block_bad_ips()
     * 
     * @return void
     */
    protected static function block_bad_ips() {
        $badips = self::get_bad_ips();
        # print_r($badips);die;

        if (in_array($_SERVER['REMOTE_ADDR'], $badips)) {
            $fp = fopen(static::$hlock_blocked_file, 'a+');
            fwrite($fp, implode("\t", array(
                date('Y-m-d H:i:s'),
                $_SERVER['HTTP_USER_AGENT'],
                'IP',
                $_SERVER['REMOTE_ADDR'])) . PHP_EOL);
            fclose($fp);
            self::exit_env('IP');
        }
    }

    /**
     * hlock::get_bad_bots()
     * 
     * @return
     */
    protected static function get_bad_bots() {
        if (is_file(static::$badbots_file)) {
            return explode(PHP_EOL, file_get_contents(static::$badbots_file));
        }
        else
            return array();
    }

    /**
     * hlock::get_bad_ips()
     * 
     * @return
     */
    protected static function get_bad_ips() {
        if (is_file(static::$badips_file)) {
            return explode(PHP_EOL, file_get_contents(static::$badips_file));
        }
        else
            return array();
    }

    /**
     * hlock::echo_table()
     * 
     * @param mixed $table
     * @param mixed $title
     * @return void
     */
    protected static function echo_table($table, $title) {
        echo '<h3>' . $title . '</h3><table>';
        foreach ((array )$table as $key => $row) {
            echo '<tr>';
            foreach ($row as $value) {
                echo '<td>' . $value . '</td>';
            }
            echo '</tr>';
        }
        echo '</table>';
    }

    /**
     * hlock::get_backend()
     * 
     * @return
     */
    public function get_backend() {
        return array(
            'bad_ips' => (implode(PHP_EOL, self::get_bad_ips())),
            'bad_bots' => (implode(PHP_EOL, self::get_bad_bots())),
            );
    }

    /**
     * hlock::save()
     * 
     * @return void
     */
    public function save() {
        $ip_list = array();
        $FORM = (array )$_POST['FORM'];
        $arr = explode(PHP_EOL, stripslashes($FORM['bad_ips']));
        foreach ($arr as $ip) {
            $ip = trim($ip);
            if (self::is_valid_ip($ip)) {
                $ip_list[] = $ip;
            }
        }
        $ip_list = array_unique($ip_list);
        file_put_contents(static::$badips_file, trim(implode(PHP_EOL, $ip_list)));
        file_put_contents(static::$badbots_file, stripslashes($FORM['bad_bots']));
    }

    /**
     * hlock::add_ip()
     * 
     * @param mixed $ip
     * @return void
     */
    public static function add_ip($ip) {
        $ip = trim($ip);
        if (self::is_valid_ip($ip)) {
            $ip_list = self::get_bad_ips();
            $ip_list[] = trim($ip);
            $ip_list = array_unique($ip_list);
            file_put_contents(static::$badips_file, implode(PHP_EOL, $ip_list));
        }
    }

    /**
     * hlock::remove_ip()
     * 
     * @param mixed $ip
     * @return void
     */
    public static function remove_ip($ip) {
        $ip_list = self::get_bad_ips();
        $ip_list = array_diff($ip_list, array($ip));
        file_put_contents(static::$badips_file, implode(PHP_EOL, $ip_list));
    }

    /**
     * hlock::is_valid_ip()
     * 
     * @param mixed $ip
     * @return
     */
    public static function is_valid_ip($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP) && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return false;
        }
        return true;
    }

    /**
     * hlock::get_query_string()
     * 
     * @return
     */
    private static function get_query_string() {
        return $_SERVER['QUERY_STRING'];
    }

    /**
     * hlock::detect_injection()
     * 
     * @return void
     */
    public static function detect_injection() {
        $cracktrack = self::get_query_string();
        $json = json_decode(self::get_black_list(), true);
        foreach ((array )$json['sqlinject'] as $row) {
            $wormprotector[] = $row['i_term'];
        }

        $checkworm = str_ireplace($wormprotector, '*', $cracktrack);
        if ($cracktrack != $checkworm) {
            self::add_ip($_SERVER['REMOTE_ADDR']);
            self::report_hack('SQL Injection blocked');
            if (static::$email != "") {
                $nachricht = 'Hacking blocked [SQLINJECTION]: ' . PHP_EOL;
                $arr = array(
                    'IP' => $_SERVER['REMOTE_ADDR'],
                    'Host' => $_SERVER['HTTP_HOST'],
                    'Trace' => 'https://www.ip-tracker.org/locator/ip-lookup.php?ip=' . $_SERVER['REMOTE_ADDR'],
                    'HTTP_USER_AGENT' => $_SERVER['HTTP_USER_AGENT'],
                    'cracktrack' => $cracktrack,
                    "Hacked" => $checkworm);
                foreach ($arr as $key => $value) {
                    $nachricht .= $key . ":\t" . $value . PHP_EOL;
                }
                $header = 'From: ' . static::$email . "\r\n" . 'Reply-To: ' . static::$email . "\r\n" . 'X-Mailer: PHP/' . phpversion();
                mail(static::$email, 'IP blocked: [SQLINJECTION] ' . $_SERVER['HTTP_HOST'], $nachricht, $header, '-f' . static::$email);
            }
            self::exit_env('INJECT');
        }
    }

    /**
     * hlock::report_hack()
     * 
     * @param mixed $type_info
     * @return void
     */
    private static function report_hack($type_info) {
        $user_agent = self::get_user_agent();
        $arr = array(
            'FORM[h_type]' => $type_info,
            'FORM[h_domain]' => $_SERVER['HTTP_HOST'],
            'FORM[h_ip]' => self::anonymizing_ip($_SERVER['REMOTE_ADDR']),
            'FORM[h_url]' => base64_encode($_SERVER['PHP_SELF'] . '###' . $_SERVER['QUERY_STRING'] . '###' . http_build_query($_REQUEST)),
            'cmd' => 'log_hacking',
            'FORM_IP[b_iphash]' => md5($_SERVER['REMOTE_ADDR'] . $user_agent),
            'FORM_IP[b_ua]' => $user_agent,
            'FORM_IP[b_ip]' => self::anonymizing_ip($_SERVER['REMOTE_ADDR']),
            );
        self::curl_get_data('https://www.keimeno.de/report-hack.html', $arr);
    }

    /**
     * hlock::get_black_list()
     * 
     * @return void
     */
    public static function get_black_list() {
        if (is_file(static::$hlock_blacklist) && (integer)(time() - filemtime(static::$hlock_blacklist)) > (static::$blacklis_lifetime_hours * 3600)) {
            @unlink(static::$hlock_blacklist);
        }

        if (!is_file(static::$hlock_blacklist)) {
            self::curl_get_data_to_file('https://www.keimeno.de/report-hack.html?cmd=get_black_iplist&FORM[host]=' . $_SERVER['HTTP_HOST'], static::$hlock_blacklist);
        }
        return file_get_contents(static::$hlock_blacklist);
    }

    /**
     * hlock::curl_get_data()
     * 
     * @param mixed $url
     * @param mixed $vars
     * @return
     */
    private static function curl_get_data($url, $vars = array()) {
        $ch = curl_init();
        $timeout = 10;
        curl_setopt($ch, CURLOPT_URL, $url);
        if (is_array($vars) && count($vars) > 0) {
            curl_setopt($ch, CURLOPT_POST, 1);
            self::http_build_query_for_curl($vars, $curl_vars);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $curl_vars);
        }
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }

    /**
     * hlock::http_build_query_for_curl()
     * 
     * @param mixed $arrays
     * @param mixed $new
     * @param mixed $prefix
     * @return void
     */
    private static function http_build_query_for_curl($arrays, &$new = array(), $prefix = null) {
        if (is_object($arrays)) {
            $arrays = get_object_vars($arrays);
        }
        foreach ($arrays as $key => $value) {
            $k = isset($prefix) ? $prefix . '[' . $key . ']' : $key;
            if (is_array($value) or is_object($value)) {
                self::http_build_query_for_curl($value, $new, $k);
            }
            else {
                $new[$k] = $value;
            }
        }
    }

    /**
     * hlock::anonymizing_ip()
     * 
     * @param mixed $ip
     * @return
     */
    private static function anonymizing_ip($ip) {
        if (strpos($ip, ".") == true) {
            return preg_replace('#(?:\.\d+){1}$#', '.0', $ip);
        }
        else {
            return preg_replace('~[0-9]*:[0-9]+$~', 'XXXX:XXXX', $ip);
        }
    }

    /**
     * hlock::curl_get_data_to_file()
     * 
     * @param mixed $url
     * @param mixed $local_file
     * @return
     */
    public static function curl_get_data_to_file($url, $local_file) {
        $fp = fopen($local_file, 'w');
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $data = curl_exec($ch);
        curl_close($ch);
        fclose($fp);
        #        echo $data;die; $failure = (strstr($data, '302 Found'));
        if ($data == false) {
            @unlink($local_file);
            return false;
        }
        if (filesize($local_file) < 10000) {
            if (strstr(file_get_contents($local_file), '302 Found')) {
                @unlink($local_file);
                return false;
            }
        }
        return true;
    }

}
