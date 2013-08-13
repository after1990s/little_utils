<?php
function splitURL($url)
{//http://music.baidu.com/song/1137385?pst=sug
	$initString = "http://music.baidu.com/data/music/fmlink?songIds=";
	$first = explode ('/', $url);
	$second = explode ('?', $first[4]);
	if (!$second[0])
	{
		return null;
	}
	else
	{
		$firstpart =  $initString . $second[0];
		$flac = $firstpart."&type=flac&rate=1024";
		$mp3320= $firstpart."&type=mp3&rate=320";
		$mp3256= $firstpart."&type=mp3&rate=256";
		$mp3128 = $firstpart."&type=mp3&rate=128";
		return array($mp3128, $mp3256, $mp3320, $flac);
	} 
}
?>
<html>
<?php
 if ($_POST['submit']=='submit')
 {

	$jsonUrlArray = splitUrl($_POST['url']);
	$i=0;
	while ($i!=3){
		$ch = curl_init();
		curl_setopt($ch,CURLOPT_URL, $jsonUrlArray[$i]);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		$result = curl_exec($ch);
		echo '<br /><br />';
		$ErrorArray = json_decode($result);
		if ($ErrorArray->{'errorCode'}!=22000)
		{
			echo 'get song fail';
			return;
		}
		$songArray = $ErrorArray->{'data'}->{'songList'};
		switch($i){
			case 0:
			echo '128k:<br/>';
			break;
			case 1:
			echo '256k:<br/>';
			break;
			case 2:
			echo '320k:<br/>';
			break;
			default:
			echo 'flac:<br/>';
		}
		echo '<a href='.$songArray[0]->{'songLink'}.'>'.$songArray[0]->{'songName'}.'</a>';
		echo '<br/>';
		curl_close($ch);
		$i = $i+1;
	}
}
 else
 {
	echo '
<form action=# method="POST">
<input type="text" name="url" value="http://music.baidu.com/song/64563148"/>
<input type="submit" name="submit" value="submit" />
</form>
';
 }
?>
</html>
