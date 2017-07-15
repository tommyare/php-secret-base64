<?php

namespace app;

use think\Controller;
use think\mongo\Connection;
use think\Request;
use think\Response;
use think\Session;
use think\Db;
use smsapi\SmsClass;

class encrypt {
    //  加密神兽开始
    //  GooPle
    //  Created by chivas on 16/7/8.
    //  Copyright (c) 2016年 GooPle. All rights reserved.
    //
    /**
     * ===================GONGCHENGWANG V2.0================
     * 　　　　　　　　┏┓　　　┏┓
     * 　　　　　　　┏┛┻━━  ━┛┻┓
     * 　　　　　　　┃　　　　　　　┃
     * 　　　　　　　┃　　　━　　 　┃
     * 　　　　　　　┃　 ┳┛　┗┳  　┃
     * 　　　　　　　┃　　　　　　　┃
     * 　　　　　　　┃   ╰┬┬┬╯  　┃
     * 　　　　　　　┃　　　　　　　┃
     * 　　　　　　　┗━┓　　　   ┏━┛
     * 　　　　　　　　　┃　　　┃
     * 　　　　　　　　　┃　　　┃    神兽保佑,代码无bug
     * 　　　　　　　　　┃　　　┃
     * 　　　　　　　　　┃　　　┃
     * 　　　　　　　　　┃　　　┃
     * 　　　　　　　　　┃　　　┃
     * 　　　　　　　　　┃　　　┗━━━┓
     * 　　　　　　　　　┃　　　　　　　┣┓
     * 　　　　　　　　　┃　　　　　　　┏┛
     * 　　　　　　　　　┗┓┓┏━┳┓┏┛
     * 　　　　　　　　　　┃┫┫　┃┫┫
     * 　　　　　　　　　　┗┻┛　┗┻┛
     */

    /**
     * 加密，可逆
     * 可接受任何字符
     * 安全度非常高
     * 加密方案二
     */
    public static function encrypt_unrand($txt, $key = 'anihc ctI') {
        if ($key == 'encrypt') {
            return $txt;
        }
        $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.)";
        $ikey = "-x6g6ZWm2G9g_vr0Bo.pOq3kRIxsZ6rm";
//        $nh1 = rand(0, 64);
//        $nh2 = rand(0, 64);
//        $nh3 = rand(0, 64);
        $nh1 = 2;
        $nh2 = 4;
        $nh3 = 12;
        $ch1 = $chars{$nh1};
        $ch2 = $chars{$nh2};
        $ch3 = $chars{$nh3};
        $nhnum = $nh1 + $nh2 + $nh3;
        $knum = 0;
        $i = 0;
        while (isset($key{$i}))
            $knum += ord($key{$i++});


        $mdKey = substr(md5(md5(md5($key . $ch1) . $ch2 . $ikey) . $ch3), $nhnum % 8, $knum % 8 + 16);
        $txt = base64_encode($txt);
        $txt = str_replace(array('+', '/', '=', '_'), array('-', '#', '.', '@', ''), $txt);
        $tmp = '';
        $j = 0;
        $k = 0;
        $tlen = strlen($txt);
        $klen = strlen($mdKey);
        //echo $tlen.'<br/>'.$klen.'<br/>';
        //exit;
        for ($i = 0; $i < $tlen; $i++) {
            $k = $k == $klen ? 0 : $k;
            $j = ($nhnum + strpos($chars, $txt{$i}) + ord($mdKey{$k++})) % 64;
            $tmp .= $chars{$j};
        }
        $tmplen = strlen($tmp);
        $tmp = substr_replace($tmp, $ch3, $nh2 % ++$tmplen, 0);
        $tmp = substr_replace($tmp, $ch2, $nh1 % ++$tmplen, 0);
        $tmp = substr_replace($tmp, $ch1, $knum % ++$tmplen, 0);
        $tmp = str_replace("_", "@", $tmp);
        return $tmp;
    }

    /**
     * 解密
     * 当密钥为encrypt时，不加密
     * 解密方案二
     */
    public static function decrypt_unrand($txt, $key = 'anihc ctI') {
        if ($key == 'encrypt') {
            return $txt;
        }
        $txt = str_replace("@", "_", $txt);
        $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
        $ikey = "-x6g6ZWm2G9g_vr0Bo.pOq3kRIxsZ6rm";
        $knum = 0;
        $i = 0;
        $tlen = strlen($txt);
        while (isset($key{$i}))
            $knum += ord($key{$i++});
        $ch1 = $txt{$knum % $tlen};
        $nh1 = strpos($chars, $ch1);
        $txt = substr_replace($txt, '', $knum % $tlen--, 1);
        if (strlen($txt) == 0) {
            //TODO错误处理
            echo '非法参数';
            exit;
        }
        $ch2 = $txt{$nh1 % $tlen};
        $nh2 = strpos($chars, $ch2);
        $txt = substr_replace($txt, '', $nh1 % $tlen--, 1);
        if (strlen($txt) == 0) {
            //TODO错误处理
            echo '非法参数';
            exit;
        }
        $ch3 = $txt{$nh2 % $tlen};
        $nh3 = strpos($chars, $ch3);
        $txt = substr_replace($txt, '', $nh2 % $tlen--, 1);
        $nhnum = $nh1 + $nh2 + $nh3;
        $mdKey = substr(md5(md5(md5($key . $ch1) . $ch2 . $ikey) . $ch3), $nhnum % 8, $knum % 8 + 16);
        $tmp = '';
        $j = 0;
        $k = 0;
        $tlen = strlen($txt);
        $klen = strlen($mdKey);
        for ($i = 0; $i < $tlen; $i++) {
            $k = $k == $klen ? 0 : $k;
            $j = strpos($chars, $txt{$i}) - $nhnum - ord($mdKey{$k++});
            while ($j < 0)
                $j += 64;
            $tmp .= $chars{$j};
        }
        $tmp = str_replace(array('-', '#', '.', '@'), array('+', '/', '=', '_'), $tmp);
        return base64_decode($tmp);
    }

}
