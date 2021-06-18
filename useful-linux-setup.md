Video Thumbnails:
  https://askubuntu.com/questions/1034595/thumbnails-not-showing-in-video-in-ubuntu-18-04
  
  sudo apt install ffmpegthumbnailer
  
  sudo apt install gstreamer1.0-libav
  
  sudo apt-get install ffmpeg ffmpegthumbnailer gstreamer*
  
  rm -rf ~/.cache/thumbnails/*
  
  rm -r ~/.cache/thumbnails/fail
  
  sudo vi /usr/share/thumbnailers/totem.thumbnailer
   ```
   [Thumbnailer Entry]
   TryExec=ffmpegthumbnailer
   Exec=ffmpegthumbnailer -s %s -i %i -o %o -c png -f -t 10
   MimeType=application/mxf;application/ogg;application/ram;application/sdp;application/vnd.ms-wpl;application/vnd.rn-realmedia;application/x-extension-m4a;application/x-extension-mp4;application/x-flash-video;application/x-matroska;application/x-netshow-channel;application/x-ogg;application/x-quicktimeplayer;application/x-shorten;image/vnd.rn-realpix;image/x-pict;misc/ultravox;text/x-google-video-pointer;video/3gpp;video/dv;video/fli;video/flv;video/mp2t;video/mp4;video/mp4v-es;video/mpeg;video/msvideo;video/ogg;video/quicktime;video/vivo;video/vnd.divx;video/vnd.rn-realvideo;video/vnd.vivo;video/webm;video/x-anim;video/x-avi;video/x-flc;video/x-fli;video/x-flic;video/x-flv;video/x-m4v;video/x-matroska;video/x-mpeg;video/x-ms-asf;video/x-ms-asx;video/x-msvideo;video/x-ms-wm;video/x-ms-wmv;video/x-ms-wmx;video/x-ms-wvx;video/x-nsv;video/x-ogm+ogg;video/x-theora+ogg;video/x-totem-stream;audio/x-pn-realaudio;audio/3gpp;audio/ac3;audio/AMR;audio/AMR-WB;audio/basic;audio/midi;audio/mp2;audio/mp4;audio/mpeg;audio/ogg;audio/prs.sid;audio/vnd.rn-realaudio;audio/x-aiff;audio/x-ape;audio/x-flac;audio/x-gsm;audio/x-it;audio/x-m4a;audio/x-matroska;audio/x-mod;audio/x-mp3;audio/x-mpeg;audio/x-ms-asf;audio/x-ms-asx;audio/x-ms-wax;audio/x-ms-wma;audio/x-musepack;audio/x-pn-aiff;audio/x-pn-au;audio/x-pn-wav;audio/x-pn-windows-acm;audio/x-realaudio;audio/x-real-audio;audio/x-sbc;audio/x-speex;audio/x-tta;audio/x-wav;audio/x-wavpack;audio/x-vorbis;audio/x-vorbis+ogg;audio/x-xm;application/x-flac;
   ```

[Ubuntu 20]: https://linuxconfig.org/ubuntu-20-04-ffmpeg-installation
$ sudo apt update    

$ sudo apt install ffmpeg    

$ sudo apt update    

$ sudo apt install libopus-dev libmp3lame-dev libfdk-aac-dev libvpx-dev libx264-dev yasm libass-dev libtheora-dev libvorbis-dev mercurial cmake build-essential    

$ mkdir ~/ffmpeg; cd ~/ffmpeg    

$ hg clone https://bitbucket.org/multicoreware/x265   

$ cd x265/build/linux    

$ PATH="$HOME/bin:$PATH" cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX="$HOME/ffmpeg_build" -DENABLE_SHARED:bool=off ../../source && PATH="$HOME/bin:$PATH"   

$ sudo make && sudo make install  

$ if [ -d ~/ffmpeg ]; then cd ~/ffmpeg; else mkdir ~/ffmpeg && cd ~/ffmpeg; fi  

$ wget -O- http://ffmpeg.org/releases/ffmpeg-snapshot.tar.bz2 | tar xj  

$ cd ~/ffmpeg/ffmpeg
PATH="$HOME/bin:$PATH" PKG_CONFIG_PATH="$HOME/ffmpeg_build/lib/pkgconfig" ./configure --prefix="$HOME/ffmpeg_build" --pkg-config-flags="--static" --extra-cflags="-I$HOME/ffmpeg_build/include" --extra-ldflags="-L$HOME/ffmpeg_build/lib" --extra-libs="-lpthread -lm" --bindir="$HOME/bin" --enable-gpl --enable-libass --enable-libfdk-aac --enable-libfreetype --enable-libmp3lame --enable-libopus --enable-libtheora --enable-libvorbis --enable-libvpx --enable-libx264 --enable-libx265 --enable-nonfree && PATH="$HOME/bin:$PATH" sudo make && sudo make install





