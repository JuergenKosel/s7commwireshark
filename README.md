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

## Update from upstream subversion

Contrary to https://git-scm.com/docs/git-svn , it is possible to run 'git svn init' inside an already exisiting git repository. So you could turn your clone of this git repository into a git-svn repository and fetch updates from the upstream svn repository. Therefore run the following commands:

    git config --add svn.addAuthorFrom true
    git config --add svn.useLogAuthor true
    git config --add svn.pushmergeinfo true
    git svn init -s ​svn://svn.code.sf.net/p/s7commwireshark/code

Create a local branch named trunk from the origin/trunk branch if you have not done so far and check it out:

    git branch trunk origin/trunk
    git checkout trunk

Update your trunk branch to the subversion trunk:

    git svn fetch
    git svn rebase
