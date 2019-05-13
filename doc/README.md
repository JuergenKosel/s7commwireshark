# Install packages for Debian Buster

Unless expired, installer packages of Wireshark with s7comm-plus
dissector integrated for Debian Buster are available as
continous integration build artifact at [gitlab.com/juergen.kosel.jk/wireshark](https://gitlab.com/juergen.kosel.jk/wireshark/-/jobs/artifacts/s7commwireshark/download?job=build-debian-deb)

# Build wireshark with s7comm_plus dissector

To build the wireshark s7comm_plus dissector, which is provided by [this project](http://sourceforge.net/projects/s7commwireshark/), you need the corresponding wireshark sources.

To get these wirshark sources, you need to install git.
Then you have at least the following 2 options:

## 1 "original" upstream sources from https://code.wireshark.org/review/wireshark
Use the "original" upstream sources by running the following command:

    git clone https://code.wireshark.org/review/wireshark

Then you need to checkout the sources of this dissector into the wireshark source tree:

     cd wireshark
     svn checkout svn://svn.code.sf.net/p/s7commwireshark/code/trunk/src plugins

Then you need to add the s7comm_plus sources to epan/dissectors/CMakeLists.txt and epan/dissectors/Makefile.am, as it is done in https://github.com/JuergenKosel/wireshark/commit/c22e6cb3b1b068746bededda5409590f6fb7b433

## 2 Use prepared wireshark git repository

Therrefore run the following commands:

    git clone https://github.com/JuergenKosel/wireshark.git wireshark
    cd wireshark
    git checkout s7commwireshark
    git submodule update --init

## Build

Finally follow the build instructions of the Wireshark project.
E.g. for Linux with cmake and other tools installed:

   mkdir build
   cd build
   cmake ..
   make -j`nproc`

To build on Windows, including the installer is described at:
https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html .
A template script to build on Windows is available in:
https://github.com/JuergenKosel/wireshark/blob/s7commwireshark/build4windows.bat
