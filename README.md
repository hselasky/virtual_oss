<IMG SRC="https://raw.githubusercontent.com/hselasky/virtual_oss/main/www/virtual_oss.svg" WIDTH="10%"></IMG> 
# Virtual OSS
Virtual OSS is an audio mixing application that multiplexes and
demultiplexes a single OSS device into multiple customizable OSS
compatible devices using character devices in userspace, cuse(4).
These devices can be used to record played back audio and mix the
individual channels in multiple ways.

Virtual OSS also supports playback and recording using bluetooth
audio devices.

## Features
<ul>
  <li>Resampling of audio</li>
  <li>Per channel equalizer</li>
  <li>Per channel compressor</li>
  <li>Up to 64 mono channels</li>
  <li>HTTP server support</li>
  <li>RTP multicast streaming</li>
  <li>Sndio support</li>
</ul>

## How to build under FreeBSD
<ul>
  <li>make all</li>
  <li>make install</li>
</ul>

## Dependencies
<ul>
  <li>libcuse</li>
  <li><A HREF="http://www.fftw.org">FFTW3</A> </li>
</ul>

## How to get help about the commandline parameters
<pre>
virtual_oss -h
</pre>

## Privacy policy

Virtual OSS does not collect any information from its users.

## Supported platforms
<ul>
  <li>FreeBSD <A HREF="https://www.freshports.org/audio/virtual_oss">Virtual OSS port</A></li>
</ul>
