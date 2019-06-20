#!/opt/local/bin/perl

use strict;
use XML::TreePP;
use Data::Dumper;
use Math::Round;
use Excel::Writer::XLSX;
use Data::Table;
use Excel::Writer::XLSX::Chart;
use Getopt::Std;
#use Devel::Size qw(size total_size);   #############  New module

print "";
## Copyright (C) 2016  Cody Dumont
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
## This is a program to parse a series of Nessus XMLv2
## files into a XLSX file.  The data from the XML file is placed into a series
## of tabs to for easier review and reporting.  New features with this edition
## are better reporting of policy plugin families, user account reporting,
## summary graphs, and a home page with summary data.  For more information
## and questions please contact Cody Dumont cody@melcara.com
##
## Version 0.24

our %recast_plugin;
our (@installedSoftware,@portScanner,@vuln_entries,@host_scan_data,@WinWirelessSSID,@cpe_data,@PCIDSS,@ADUsers,@ScanInfo,@MS_Process_Info);
our (@WinUserData,@WinUsers,@WinGuestUserData,@PasswordPolicyData,@WirelessAccessPointDetection,@DeviceType,@EnumLocalGrp);
our $highvuln_cnt = 0;
our $medvuln_cnt = 0;
our $lowvuln_cnt = 0;
our $nonevuln_cnt = 0;
our $PolicySummaryReport_worksheet;
our $PolicySummaryReport_cnt;
our $center_format;
our $center_border6_format;
our $cell_format;
our $wrap_text_format;
our $workbook;
my $is_domain_controller_users_checked = 0;
our %complaince;
our %compliance_summary;
our %audit_result_type;
our %vulnerability_data;
our %ip_vuln_data;
our %ms_process_cnt;
our $home_url;
our $url_format;
my @targets;
my $target_cnt;
our $ip_add_regex = '(25[0-5]|[2][0-4][0-9]|1[0-9]{2}|[\d][\d]|[\d])(\.(25[0-5]|[2][0-4][0-9]|1[0-9]{2}|[\d][\d]|[\d])){3}';
my $dir;
my $target_file;
my @xml_files;
our %cvss_score;
our $port_scan_plugin = '(10335)|(34277)|(11219)|(14272)|(34220)';
our $installed_software_plugin = '(20811)|(58452)|(22869)';
our %total_discovered;
our %vuln_totals;
our @host_data;
my @PolicyCompliance;
my @policy_data;

my $new_stuff = '
These are the new features with version 24

1.  Fix regex \Q\E line est 1477,1484 v22
2.  Removing plugin 33929 from High Vulns calculation
3.  Removed Compliance from being part of High Vuln Calculation
4.  Version 23 Skipped
5.  reordered vuln data processing to not use as much memory.
6.  
7. 
8.  
9.  
';

print $new_stuff;
sleep 2;

#####################  get arguments from the command
my $help_msg = '
NAME
    parse_nessus_xml.v24.pl -- parse nessus v2 XML files into an XLSX file
    
SYNOPSIS
    perl parse_nessus_xml.v24.pl [-vVhH] [-f file] [-d directory] [-r recast_file optional ]

DESCRIPTION
    Nessus Parser v0.24 - This is a program to parse a series of Nessus XMLv2
    files into a XLSX file.  The data from the XML file is placed into a series
    of tabs to for easier review and reporting.  New features with this edition
    are better reporting of policy plugin families, user account reporting,
    summary graphs, and a home page with summary data.  For more information
    and questions please contact Cody Dumont cody@melcara.com
    
    The Nessus parser requires some additional modules, they are:
    o	XML::TreePP
    o	Data::Dumper
    o	Math::Round
    o	Excel::Writer::XLSX
    o	Data::Table
    o	Excel::Writer::XLSX::Chart
    o	Getopt::Std

    The options are as follows:
    -o      Changes the filename prefix.  The default prefix is "nessus_report".
            A time stamp is appended onto the prefix.  An exmaple of the default
            file name is nessus_report_20130409162908.xlsx.  if the "-o foobar" is
            passed, then the file name will be foobar_20130409162908.xlsx
    
    -d      The target directory where the Nessus V2 XML files are located.
            This option will search the target directory files that end with
            XML, xml, or nessus extentions.  Each file found will be check for
            Nessus V2 XML format.  Each Nessus V2 XML file will be parsed and
            will be stored into an XLSX file.  This option should not be used
            with any other option.

    -f      The target file is a method to call a single file for parsing.
            With this method the XLSX file will be stored in the same folder
            as the XML.  Please note if the path to file has a "SPACE" use
            double quotes around the file path and/or name.

    -r      The Recast option is a feature request from user KurtW.  Kurt wanted
            to be able to change the reported value of Nessus Plugin ID.  While
            this is not recommended in many cases, in some instances the change
            may provide the Nessus user with more accurate report.
            To use this feature create a CSV file with three fields.
            
            Field 1:  Nessus Plugin ID
            Field 2:  Nessus-assigned Severity
            Field 3:  Recasted (User-assigned) Severity
            
            Examples
            
            # Recast vulnerability SSL Certificate Cannot Be Trusted (Plugin ID 51192) from Medium to Critical
            51192,2,4
            
            # Recast vulnerability MySQL 5.1 < 5.1.63 Multiple Vulnerabilities (Plugin ID 59448) from High to Low
            59448,3,1
            
            # Recast vulnerability MS12-067: Vulnerabilities in FAST Search Server 2010 for Sharepoint RCE from High to Critical
            62462,3,4
            
            The file would contain 3 lines.
            51192,2,4
            59448,3,1
            62462,3,4
            
            The command used would be passed the -r recast.txt.  See examples listed below.

    -v      Print this help message.

    -h      Print this help message.
    
    EXAMPLES
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -v
            
            This command will print this help message.
        
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -h
            
            This command will print this help message.
        
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -d /foo/bar
            
            This command will seearch the direcoty specified by the "-d" option
            for Nessus XML v2 files and parse the files found.
        
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -f /foo/bar/scan1.nessus
                -----  or -----
                perl /path/to/script/parse_nessus_xml.v24.pl -f /foo/bar/scan1.nessus.xml
            
            This command will seearch the direcoty specified by the "-d" option
            for Nessus XML v2 files and parse the files found.
            
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -f /foo/bar/scan1.nessus -r /path/to/script/recast.txt
                
';

my $version = $ARGV[0];
my %opt;
getopt('dfro', \%opt);

if($version =~ /-(v|V|h|H)/){
    print $help_msg;exit;
}
elsif($opt{"d"} && $opt{"f"}){
    print "Please only use a file or directory as a command line argument.\n\n";
    print $help_msg;exit;
}
elsif($opt{"d"}){
    $dir = $opt{"d"};
    print "The target directory is \"$dir\"\.\n";
    opendir DIR, $dir;
    my @files = readdir(DIR);
    closedir DIR;
    my @xml = grep {$_ =~ /((xml)|(XML)|(nessus))$/} @files;
    #@xml_files = grep {$_ !~ /^\./} @xml_files;
    my @verified;
    my $eol_marker = $/;
    undef $/;
    
    foreach (@xml){
        my $f = "$dir/$_";
        open FILE, $f;
        my $tmp_data = <FILE>;
        close FILE;
        if($tmp_data =~ /(NessusClientData_v2)/m){print "File $_ is a Valid Nessus Ver2 format and will be parsed.\n\n";push @verified,$f}
        else{print "This file \"$_\" is not using the Nessus version 2 format, and will NOT be parsed!!!\n\n";}
    }
    # end of foreach (@xml)
    $/ = $eol_marker;
    @xml_files = @verified;
}
elsif($opt{"f"}){
    $target_file = $opt{"f"};
    print "The target file is \"$target_file\"\.\n";
    my $eol_marker = $/;
    undef $/;
    open FILE, $target_file;
    my $tmp_data = <FILE>;
    close FILE;
    if($tmp_data =~ /(NessusClientData_v2)/m){
        print "File $target_file is a Valid Nessus Ver2 format and will be parsed.\n\n";
        my @dirs = split /\\|\//,$target_file;
        pop @dirs;
        if(!@dirs){push @dirs, "."}
        $dir = join "/", @dirs;
        push @xml_files, $target_file;
        
        print "";
    }
    else{print "This file \"$target_file\" is not using the Nessus version 2 format, and will NOT be parsed!!!\n\n";exit;}
    $/ = $eol_marker;
}
else{
    print $help_msg;exit;
}

if($opt{"r"}){
    my $recast_file = $opt{"r"};
    print "The recast option is selected, the recast definition file is \"$recast_file\"\.\nPlease note all the following Plugin ID's will have thier severity changed accordingly.\n\n";
    open FILE, $recast_file or die "Can't open the $recast_file file\n";
    my @tmp_data = <FILE>;
    close FILE;
    chomp @tmp_data;
    print "PLUGIN ID\tOLD SEV\tNEW SEV\n";
    foreach my $p (@tmp_data){
        my @t = split /\,/,$p;
        if($t[3]){print "There is a error in your RECAST file, please review the help message using the -h option.\n";exit;}
        print "$t[0]\t\t$t[1]\t$t[2]\n";
        $recast_plugin{$t[0]}->{old} = $t[1];
        $recast_plugin{$t[0]}->{new} = $t[2];
    }
}


