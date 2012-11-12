#!/usr/bin/perl

##
# keepass - KeePassX Command Line Interface
#
# Author: Danilo Abbasciano <piuma _at_ piumalab.org>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
##

use Data::Dumper qw(Dumper);
use Getopt::Long qw(:config bundling);
use Term::ReadKey;
use String::Random;
use File::KeePass 2.03;      # non-core, >=v0.03 needed due critical bug fixes
use Clipboard;

use constant DEFAULT_FILE => '~/.keepassx.kdb'; # default file

#
# main
#

$sFile = DEFAULT_FILE;
$sPassPhrase = null;

my $oKeePass = File::KeePass->new;
my $sPassPhrase = '';

options();

if ($fCreateDb) {
    if (-e $sFile) {
	print "$sFile already exists\n";
	exit 1;
    }

    $oKeePass->add_group({title => 'Internet', });

    $oKeePass->add_group({title => 'eMail', });

    $oKeePass->unlock;
    $oKeePass->save_db($sFile, readPassphrase());

    exit 1;
}

msg("open file: $sFile");

if (! -e $sFile) {
    print "Can't open $sFile: No such file or directory\n";
    exit 1;
}


printWhatIDoMessage();

while (! eval { $oKeePass->load_db($sFile, readPassphrase()) }) {
    print "Passphrase is incorrect\n";

    msg("Couldn't load the file $sFile: $@");
}

# add entry
if ($fAddEntry) {
    addEntry();
    exit 1;
}

if ($fLongListing) {
    msg("Long listing of all entries");
    printLongList($oKeePass);
    $oKeePass->clear;
    exit 0;
}

#$oKeePass->unlock;
#print Dumper $oKeePass->groups; # passwords are now visible

my $oEntry = $oKeePass->find_entry({title => $sTitle});

if (!$oEntry) {
    print "No matching entries\n";
    exit 1;
}

msg(Dumper $oEntry);

if ($fUserName) {
    msg('username copyed');
    Clipboard->copy($oEntry->{'username'});

    if ($fEcho) {
	print "username for ${sTitle}: " . $oEntry->{'username'} . "\n";
    }
}

if ($fPassword) {
    msg('password copyed');
    Clipboard->copy($oKeePass->locked_entry_password($oEntry));
    if ($fEcho) {
	print "password for ${sTitle}: " . $oKeePass->locked_entry_password($oEntry) . "\n";
    }

}

$oKeePass->clear;
exit 0;

#
# Functions
#

sub options () {

    # Process options.
    if ( @ARGV > 0 ) {
        GetOptions('f|file=s'=> \$sFile,
		   'l' => \$fLongListing,
		   'u|username' => \$fUserName,
		   'p|password' => \$fPassword,
		   'E|echo' => \$fEcho,
#		   'o|output=s' => \$fFileOutput,
		   'a|add' => \$fAddEntry,
		   'c|createdb' => \$fCreateDb,
		   'h|?|help' => \$fHelp,
		   'v|verbose' => \$fVerbose,
		   'V|version' => \$fVersion)
            or help();
    }
    if ($fHelp) {
	help();
    }

    if ($fVersion) {
	version();
    }

    ($sTitle) = @ARGV;

    if ($sTitle eq '' && !$fAddEntry) {
	msg("long listing setted to true");
	$fLongListing = true;
    }
}

sub msg($) {
    my ($sMessage) = shift;

    print STDERR $sMessage . "\n" if $fVerbose;
}

sub addEntry() {
    our $sPassPhrase;

    msg("Add a new entry");
# title
# username (name)
# comment
# url

    print "title: ";
    my $sTitle = <STDIN>;
    chomp $sTitle;

# group ??

    print "username: ";
    my $sUsername = <STDIN>;
    chomp $sUsername;   

  PASSWORD:

    print "password [return for random]: ";
    my $sPassword = <STDIN>;
    chomp $sPassword;
    
    if ($sPassword eq '') {
	print "Generate random password? [y] ";
	$sLine = ReadLine(0);
	if ($sLine eq "y\n" || $sLine eq "\n") {
	    my $sChoice = '';
	    my $nLength = 36;
	    my $nIndexPattern = 0;
	    my @sPattern = ("alpha/digit/symbol", "alpha/digit", "digits only");

	    do {
		
		$sPassword = getRandomPassword($nLength, $nIndexPattern);
		print "Use $sPassword \n";
		
		print "type $sPattern[$nIndexPattern], length $nLength [y/N/ /+/-/q/?] ? ";
		ReadMode("raw");
		$sChoice = ReadKey(0);
		ReadMode("normal");
		print "$sChoice\n";

		# chomp $sChoice;

		if ($sChoice eq ' ') {
		    $nIndexPattern = ($nIndexPattern + 1) % 3;		    
		}
		elsif ($sChoice eq '+') {
		    $nLength += 4;
		} 
		elsif ($sChoice eq '-') {
		    if ($nLength > 5) {
			$nLength -= 4;
		    }
		}
		elsif ($sChoice eq '?') {
		    print "Commands:\n";
		    print "  y        Yes, accept this password\n";
		    print "  N        No, generate another password of same type\n";
		    print "  <space>  Cycle through password types\n";
		    print "  -        Lower the password length\n";
		    print "  +        Raise the password length\n";
		    print "  q        Quit\n";
		    print "  ?        Help\n";
		}
		elsif ($sChoice eq 'q') {
		    goto PASSWORD;
		}

	    } while ($sChoice ne "y");

	}
	else {
	    print "password again: ";
	    $sPassword = <STDIN>;
	    chomp $sPassword;
	}
    }

    print "url [<none>]: ";
    my $sUrl = <STDIN>;
    chomp $sUrl;
    
    print "comment [<none>]: ";
    my $sComment = <STDIN>;
    chomp $sComment;

    # I must unlock the passwords before adding new entries.
    $oKeePass->unlock;

    my $e = $oKeePass->add_entry({
        title    => $sTitle,
        group    => $gid, # group id o il risultato di find_group
        # OR group => $group,
        username => $sUsername,
        password => $sPassword,
	url      => $sUrl,
	comment  => $sComment});


    $oKeePass->save_db($sFile, $sPassPhrase);
}

sub getRandomPassword($$) {
    my $nLength = shift;
    my $nIndexPattern = shift;

    my $oStringRandom = new String::Random;
    
#   c      Any lowercase character [a-z]
#   C      Any uppercase character [A-Z]
#   n      Any digit [0-9]
#   !      A punctuation character [~`!@$%^&*()-_+={}[]|\:;"'.<>?/#,]
#   .      Any of the above
#   s      A "salt" character [A-Za-z0-9./]
#   b      Any binary data

    $oStringRandom->{'A'} = [ 'A'..'Z', 'a'..'z', '0'..'9' ];

    my @aPatterns = ('.', # alpha/digit/symbol
		     'A', # alpha/digit
		     'n'  # digits only
	);
    
    msg("Index Pattern: $nIndexPattern");
    msg("Password pattern: " . $aPatterns[$nIndexPattern] x $nLength);

    $sPassword = $oStringRandom->randpattern($aPatterns[$nIndexPattern] x $nLength);
    
    return $sPassword;
}

sub readPassphrase() {
    our $sPassPhrase;

    print "Enter passphrase for $sFile: ";

    # uncomment for debug
    #$sPassPhrase = 'password';
    #print "\n";
    #return $sPassPhrase;


    ReadMode('noecho');
    $sPassPhrase = ReadLine(0);
    ReadMode 'normal';
    chomp $sPassPhrase;

    print "\n";

    return $sPassPhrase;
}

sub printLongList() { # $oKeePass
    my ($oKeePass) = shift;

    # print Dumper $oKeePass; # passwords are locked

    print "=" x 30 . "\n";

    if (defined($oKeePass->{'groups'})) {
	foreach $oGroup (values $oKeePass->{'groups'}) {
	
	    printLongListGroup($oGroup, '');
	}
    }
}

sub printLongListGroup() { # $oGroup $sGroupName
    my ($oGroup) = shift;
    my $sGroupName = shift;

    if (defined($oGroup->{'title'})) {
	$sGroupName = $sGroupName . '/' . $oGroup->{'title'};

	print "##\n# Group: ${sGroupName}\n##\n";
   
	printEntries($oGroup);

	if (defined($oGroup->{'groups'})) {
	    foreach $oSubGroup (values $oGroup->{'groups'}) {
		printLongListGroup($oSubGroup, $sGroupName);
	    }
	}
    }
}


sub printEntries() { # $oGroup
    my ($oGroup) = shift;

    if (defined($oGroup->{'entries'})) {

	foreach $oEntry (values $oGroup->{'entries'}) {
	    # print Dumper $oEntry;

	    if ($oEntry->{'title'} eq 'Meta-Info' && $oEntry->{'username'} eq 'SYSTEM') {
		next;
	    }

	    print "[" . $oEntry->{'title'} . "]\n";
	    print "   Username: " . $oEntry->{'username'} . "\n";
	    if ($oEntry->{'comment'} ne '') {
		print "   Comment : " . $oEntry->{'comment'} . "\n";
	    }
	    if ($oEntry->{'url'} ne '') {
		print "   URL     : " . $oEntry->{'url'} . "\n";
	    }

	}
    }
}

sub printWhatIDoMessage() {

    if ($fAddEntry) {
	return;
    }

    print "Going to ";

    if ($fEcho || $fLongListing) {
	print "print ";
    }
    else {
	print "copy ";
    }

    if ($fUserName) {
	print "username ";
	if ($fPassword) {
	print "and "
	}
    }
    if ($fPassword) {
	print "password ";
    }
    if ($fLongListing) {
	print "list ";
    }

    if ($fEcho || $fLongListing) {
	print "to stdout\n";
    }
    else {
	print "to X selection\n";
    }
}

sub version() {
    print "keepass - commandline tool compatible with KeePassX\n";
    print "Version 0.1\n";
    exit 1;
}

sub help() {
    $sMessage = <<END;
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
END
    print $sMessage;
    exit 1;
}
