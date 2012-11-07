keepass
=======

Command line interface to work with KeePass database file. The usage mode is inspired by pwsafe command

Command line
============

```shell
$ ./keepass.pl --help
keepass - commandline tool compatible with KeePassX
Usage: keepass [OPTION] [NAME]
Options:
  -f, --file=DATABASE_FILE   specify the database file (default is ~/.keepass.kdb)
  -l                         long listing (show username & notes) [default]
  -u, --username             emit username of listed account
  -p, --password             emit password of listed account
  -E, --echo                 force echoing of entry to stdout
  -a, --add                  add an entry
  -c, --createdb             create an empty database
  -v, --verbose              print more information (can be repeated)
  -h, --help                 display this help and exit
  -V, --version              output version information and exit
```
