#!/usr/bin/env perl

use warnings;
use strict;

use POSIX;
use File::Basename;
use Data::Dumper;
use Getopt::Long;
use JSON::PP;
use HTTP::Tiny;

my $SCRIPT_DIR = dirname(__FILE__);

sub readAllText
{
	my ($path) = @_;

	open my $fd, $path or die "Could not open $path: $!\n";
	my $text = do { local $/; <$fd> };
	close($fd);

	return $text;
}


my $commands = decode_json(readAllText("compile_commands.json"));
foreach my $command ( @{ $commands } ) {
	my $file = $command->{file};
	print($file . "\n");
}
