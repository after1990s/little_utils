/***********************************************************************
  Copyright [2013] [after1990s]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 ************************************************************************/
// ==UserScript==
// @name baidumusicdownloader
// @namespace http://after1990s.info/
// @description download baidu music
// @include http://music.baidu.com/song/*
// @exlude *
// @require http://ajax.googleapis.com/ajax/libs/jquery/1.6.0/jquery.js
// ==/UserScript==


$(document).ready(function(){
	var re=new RegExp('\\d+','m');
	var music_linkpage=window.location.href;
	var music_id = re.exec(music_linkpage);
	GM_log('href='+music_linkpage);
	if (music_id==null)
	{
		GM_log('get music_id fail');
		return false;
	}
	var json_query_string = 'http://music.baidu.com/data/music/fmlink?songIds=';
	var load_string = new Array(json_query_string + music_id[0] + '&type=mp3&rate=128',
								json_query_string + music_id[0] + '&type=mp3&rate=192',
								json_query_string + music_id[0] +"&type=mp3&rate=256",
								json_query_string + music_id[0] +"&type=mp3&rate=320",
								json_query_string + music_id[0] +"&type=flac&rate=1024");
	var download_url_prefix = 'http://music.baidu.com/data/music/file?link=';
	var div_download = $('<div id="div_download"></div>');
	div_download.insertAfter('.down-pc');
	$('<a id="download_128" >128k</a>').appendTo('#div_download');
	$('<br />').appendTo('#div_download');
	$('<a id="download_192" >192k</a>').appendTo('#div_download');
	$('<br />').appendTo('#div_download');
	$('<a id="download_256" >256k</a>').appendTo('#div_download');
	$('<br />').appendTo('#div_download');
	$('<a id="download_320" >320k</a>').appendTo('#div_download');
	$('<br />').appendTo('#div_download');
	$('<a id="download_flac" >flac</a>').appendTo('#div_download');
	GM_log('load_string:'+load_string[0]);
	GM_xmlhttpRequest({method:"GET",
		url:load_string[0], 
		onload: function(d){
          	var data = $.parseJSON(d.response);
			console.log(data);
            if (data.errorCode!=22000){
                return;
            }
			if (!data.data.songList[0].songLink)
			{
				$('#download_128').css('display','none');
				return false;
			}
            $('#download_128').attr('href',download_url_prefix+data.data.songList[0].songLink);
            return false;
        }});
    GM_xmlhttpRequest({method:"GET",
		url:load_string[1], 
		onload: function(d){
          	var data = $.parseJSON(d.response);
			console.log(data);
            if (data.errorCode!=22000){
                return;
            }
			if (!data.data.songList[0].songLink)
			{
				$('#download_192').css('display','none');
			}
            $('#download_192').attr('href',download_url_prefix+data.data.songList[0].songLink);
            return false;
        }});
    GM_xmlhttpRequest({method:"GET",
		url:load_string[2], 
		onload: function(d){
          	var data = $.parseJSON(d.response);
			console.log(data);
            if (data.errorCode!=22000){
                return;
            }
			if (!data.data.songList[0].songLink)
			{
				$('#download_256').css('display','none');
				return false;
			}
            $('#download_256').attr('href',download_url_prefix+data.data.songList[0].songLink);
            return false;
        }});
    GM_xmlhttpRequest({method:"GET",
		url:load_string[3], 
		onload: function(d){
          	var data = $.parseJSON(d.response);
			console.log(data);
            if (data.errorCode!=22000){
                return;
            }
			if (!data.data.songList[0].songLink)
			{
				$('#download_320').css('display','none');
				return false;
			}
            $('#download_320').attr('href',download_url_prefix+data.data.songList[0].songLink);
            return false;
        }});
		    GM_xmlhttpRequest({method:"GET",
		url:load_string[4], 
		onload: function(d){
          	var data = $.parseJSON(d.response);
			console.log(data);
            if (data.errorCode!=22000){
                return;
            }
			if (!data.data.songList[0].songLink)
			{
				$('#download_flac').css('display','none');
				return false;
			}
            $('#download_flac').attr('href',download_url_prefix+data.data.songList[0].songLink);
            return false;
        }});
});