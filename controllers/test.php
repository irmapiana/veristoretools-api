<?php

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$key = 'IMPORTS';

if(!$redis->get($key)) {
    $source = 'MySQL Server';
    $database_name = 'veristoretools2';
    $database_user = 'veristoretools2';
    $database_password = 'Vfi1234!';
    $mysql_host = '14.194.75.233:3306';

    $pdo = new PDO('mysql:host=' . $mysql_host . '; dbname=' . $database_name, $database_user, $database_password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $sql  = "SELECT * FROM import";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
       $imports[] = $row;
    }

    $redis->set($key, serialize($imports));
    $redis->expire($key, 100000);

} else {
     $source = 'Redis Server';
     $imports = unserialize($redis->get($key));

}

echo $source . ': <br>';
print_r($imports);