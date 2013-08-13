<?php
if ($_GET['method']=="getip"){
	$file = fopen("remoteip", "r");
	echo fread($file, 10086);
	fclose($file);
}
else if ($_GET['method']=="writeip")
{
	$file = fopen("remoteip", "w");
	fwrite($file, $_SERVER["REMOTE_ADDR"].'  ');
	fwrite($file, date("Y-m-d H:i:s", time()) ); 
	fclose($file);
}
else{
echo '<GET>method="getip"';
}

?>
<html>



</html>