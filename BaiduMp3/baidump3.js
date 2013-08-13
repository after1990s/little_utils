$(document).ready(function(){
    $('#parse_result').hide();
    $('#download_url').click(function(){
         $('#parse_result').slideUp();
        var re = new RegExp('\\d+','m');
        var music_linkpage = $('#music_linkpage').val();
        var music_id = re.exec(music_linkpage);
        if (music_id==null)
        {
            $('#error').text('url error');
        }
        var init_string='http://music.baidu.com/data/music/fmlink?songIds=';
        var load_string_128 = init_string + music_id[0] +"&type=mp3&rate=128&callback=?";
        $.getJSON(load_string_128, function(data){//获得json后
            if (data.errorCode!=22000){
                $('#error').text('server error');
                return;
            }
            $('#song_name').text(data.data.songList[0].songName);
            $('#song_downlink_128 a').attr('href',data.data.songList[0].songLink);
        });
         var load_string_256 = init_string + music_id[0] +"&type=mp3&rate=256&callback=?";
        $.getJSON(load_string_256, function(data){//获得json后
            if (data.errorCode!=22000){
                $('#error').text('server error');
                return;
            }
            $('#song_name').text(data.data.songList[0].songName);
            $('#song_downlink_256 a').attr('href',data.data.songList[0].songLink);
        });

        var load_string_320 = init_string + music_id[0] +"&type=mp3&rate=320&callback=?";
        $.getJSON(load_string_320, function(data){//获得json后
            if (data.errorCode!=22000){
                $('#error').text('server error');
                return;
            }
            $('#song_name').text(data.data.songList[0].songName);
             $('#song_downlink_320 a').attr('href',data.data.songList[0].songLink);
        });

        var load_string_flac = init_string + music_id[0] +"&type=flac&rate=1024&callback=?";
        $.getJSON(load_string_flac, function(data){//获得json后
            if (data.errorCode!=22000){
                $('#error').text('server error');
                return;
            }
            $('#song_name').text(data.data.songList[0].songName);
            $('#song_downlink_flac a').attr('href',data.data.songList[0].songLink);
        });     
        $('#parse_result').slideDown();
        return false; 
    });
});
//"http://api.taobao.com/apitools/ajax_props.do&jsoncallback=?
//"http://music.baidu.com/data/music/fmlink?songIds=907397&type=mp3&rate=128&jsoncallback=?"