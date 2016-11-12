# s7commwireshark
S7comm Wireshark dissector plugin

This project is a clone from ​http://sourceforge.net/projects/s7commwireshark/.

It was initially cloned by the following command:

    git svn clone -s --add-author-from --use-log-author ​svn://svn.code.sf.net/p/s7commwireshark/code s7commwireshark-code 


Updates are fetched by:

    git svn fetch --add-author-from --use-log-author 
    git svn rebase --add-author-from --use-log-author

The s7comm_plus dissector is intended to be used as a sub-project of Wireshark, e.g.:

    git clone https://github.com/JuergenKosel/wireshark.git wireshark
    cd wireshark
    git checkout s7commwireshark
    git submodule update --init

Then follow the build instructions of the Wireshark project.
