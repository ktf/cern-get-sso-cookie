#
#
# access CERN SSO protected pages using curl-like interface
#
#
package WWW::CERNSSO::Auth;

use strict;
use warnings;
use WWW::Curl::Easy qw(/^CURLOPT_/ /^CURLINFO_/);
use Digest::MD5 qw(md5_hex);
use URI::Escape qw(uri_escape);
use HTML::Entities qw(decode_entities);
use File::Temp qw(tempfile);
use vars qw(@ISA);
use Data::Dumper;

use constant VERSION => '0.5.1';

use constant CERN_SSO_HTTPONLY => '#HttpOnly_';
use constant CERN_SSO_COOKIE_LIFETIME => 86400;
use constant CERN_SSO_CURL_USER_AGENT_KRB => 'curl-sso-kerberos/'.VERSION.' (Mozilla)';
use constant CERN_SSO_CURL_USER_AGENT_CERT => 'curl-sso-certificate/'.VERSION. '(Mozilla)';
#use constant CERN_SSO_CURL_ADFS_EP => '/adfs/ls/auth'; (09.2013 - changed for MS ADFS patch ms13-066)
use constant CERN_SSO_CURL_ADFS_EP => '/adfs/ls';
use constant CERN_SSO_CURL_ADFS_SIGNIN => 'wa=wsignin1.0';
use constant CERN_SSO_CURL_AUTHERR => 'HTTP Error 401.2 - Unauthorized';
use constant CERN_SSO_CURL_CAPATH => '/etc/pki/tls/certs/';

use constant CURLAUTH_GSSNEGOTIATE => (1 << 2); # not defined in WWW::Curl .. nor in Net::Curl
use constant CURLCERTINFO => (0x400000 + 32); #not defined on SLC5 CURLINFO_CERTINFO
use constant FALSE => 0;
use constant TRUE  => 1;

my $setcurlout = sub {
 my($self)=@_;
 close($self->{_OUTFILE}) if ($self->{_OUTFILE});
 open($self->{_OUTFILE},">",\$self->{_OUTDATA});
 $self->{_CH}->setopt(CURLOPT_WRITEDATA,\$self->{_OUTFILE});
 close($self->{_HEADFILE}) if ($self->{_HEADFILE});
 open($self->{_HEADFILE},">",\$self->{_HEADDATA});
 $self->{_CH}->setopt(CURLOPT_WRITEHEADER,\$self->{_HEADFILE});
};


my $getinfo = sub {
 my($self)=@_;
 my %rethash= ( 
   'url'                     => $self->{_CH}->getinfo(CURLINFO_EFFECTIVE_URL),
   'http_code'               => $self->{_CH}->getinfo(CURLINFO_HTTP_CODE),
   'content_type'            => $self->{_CH}->getinfo(CURLINFO_CONTENT_TYPE),
   'header_size'             => $self->{_CH}->getinfo(CURLINFO_HEADER_SIZE),
   'request_size'            => $self->{_CH}->getinfo(CURLINFO_REQUEST_SIZE),
   'filetime'                => $self->{_CH}->getinfo(CURLINFO_FILETIME),
   'ssl_verify_result'       => $self->{_CH}->getinfo(CURLINFO_SSL_VERIFYRESULT),
   'redirect_count'          => $self->{_CH}->getinfo(CURLINFO_REDIRECT_COUNT),
   'total_time'              => $self->{_CH}->getinfo(CURLINFO_TOTAL_TIME),
   'namelookup_time'         => $self->{_CH}->getinfo(CURLINFO_NAMELOOKUP_TIME),
   'connect_time'            => $self->{_CH}->getinfo(CURLINFO_CONNECT_TIME),
   'pretransfer_time'        => $self->{_CH}->getinfo(CURLINFO_PRETRANSFER_TIME),
   'size_upload'             => $self->{_CH}->getinfo(CURLINFO_SIZE_UPLOAD),
   'size_download'           => $self->{_CH}->getinfo(CURLINFO_SIZE_DOWNLOAD),
   'speed_download'          => $self->{_CH}->getinfo(CURLINFO_SPEED_DOWNLOAD),
   'speed_upload'            => $self->{_CH}->getinfo(CURLINFO_SPEED_UPLOAD),
   'download_content_length' => $self->{_CH}->getinfo(CURLINFO_CONTENT_LENGTH_DOWNLOAD),
   'upload_content_length'   => $self->{_CH}->getinfo(CURLINFO_CONTENT_LENGTH_UPLOAD),
   'starttransfer_time'      => $self->{_CH}->getinfo(CURLINFO_STARTTRANSFER_TIME),
   'redirect_time'           => $self->{_CH}->getinfo(CURLINFO_REDIRECT_TIME),
   'certinfo'                => $self->{_CH}->getinfo(CURLCERTINFO),
   'request_header'          => $self->{_CH}->getinfo(CURLINFO_HEADER_OUT),
 );
return (\%rethash);
};


sub new {
 my($class,$cookiefile,$krb,$sslnoverify,$cert,$key,$cacert,$capath,$verbose,$debug) = @_;
 my($self) = bless {_CH => undef,
                    _DEBUG => undef,
		    _DEBUGCURL => undef, 
                    _OUTDATA => undef,
                    _OUTFILE => undef,
                    _HEADDATA => undef,
                    _HEADFILE => undef,
                    _SSO_COOKIEFH => undef,
                    _SSO_COOKIEFILE => undef,
		    _CURL_PRIVDATA => undef,
             }, $class;



$self->{_DEBUG}=1 if ($verbose);
$self->{_DEBUGCURL}=1 if ($debug);


$self->{_CH}= WWW::Curl::Easy->new();

# wait for 4.15 ..
#$self->{_CH}->setopt(CURLOPT_PRIVATE,TRUE);

if(defined($sslnoverify) && $sslnoverify==1) {
  $self->{_CH}->setopt(CURLOPT_SSL_VERIFYPEER, 0);
  $self->{_CH}->setopt(CURLOPT_SSL_VERIFYHOST, 0);
  print STDERR "CERNSSO: Warning: SSL Peer / Host Verification disabled.\n" if ($self->{_DEBUG});
 } else {
  $self->{_CH}->setopt(CURLOPT_SSL_VERIFYPEER, 1);
  $self->{_CH}->setopt(CURLOPT_SSL_VERIFYHOST, 2);
 }

 if(defined($krb) && $krb == 1) {
  print STDERR "CERNSSO: Using Kerberos credentials to authenticate.\n" if ($self->{_DEBUG});
  $self->{_CH}->setopt(CURLOPT_USERAGENT,CERN_SSO_CURL_USER_AGENT_KRB);
  $self->{_CH}->setopt(CURLOPT_HTTPAUTH,CURLAUTH_GSSNEGOTIATE);
 } else {
  print STDERR "CERNSSO: Using Certificate/Key to authenticate.\n" if ($self->{_DEBUG});
  $self->{_CH}->setopt(CURLOPT_USERAGENT,CERN_SSO_CURL_USER_AGENT_CERT);
  
  if (!defined($cert) || !defined($key)) {
   print STDERR "CERNSSO: Error: Missing certificate/key\n."; exit 1;
  }
  
  $self->{_CH}->setopt(CURLOPT_SSLCERT,$cert);
  print STDERR "CERNSSO: CERT: $cert\n" if ($self->{_DEBUG});
  #$self->{_CH}->setopt(CURLOPT_SSLCERTTYPE,"PEM");
  $self->{_CH}->setopt(CURLOPT_SSLKEY,$key);
  print STDERR "CERNSSO: KEY: $key\n" if ($self->{_DEBUG});
  #$self->{_CH}->setopt(CURLOPT_SSLKEYTYPE, "PEM");
  #$self->{_CH}->setopt(CURLOPT_SSLKEYPASSWD, XXX);
 }

if(defined($cookiefile)) {
  $self->{_SSO_COOKIEFILE}=$cookiefile;
} else {
  ($self->{_SSO_COOKIEFH},$self->{_SSO_COOKIEFILE})=tempfile(UNLINK=>1);
}

$self->{_CH}->setopt(CURLOPT_USERPWD,':');

$self->{_CH}->setopt(CURLOPT_CAINFO,$cacert) if (defined($cacert));
print STDERR "CERNSSO: CAINFO: $cacert\n" if (defined($cacert) && $self->{_DEBUG});

if (defined($capath)) { 
 $self->{_CH}->setopt(CURLOPT_CAPATH,$capath);
 print STDERR "CERNSSO: CAPATH: $capath'\n" if ($self->{_DEBUG});
} else {
 # not everybody has certsd imported in NSS db
 # and we do not include CERN certs in ca-bundle.crt ... 
 $self->{_CH}->setopt(CURLOPT_CAPATH,CERN_SSO_CURL_CAPATH);
 print STDERR "CERNSSO: CAPATH: ".CERN_SSO_CURL_CAPATH." (default)\n" if ($self->{_DEBUG});
}


$self->{_CH}->setopt(CURLOPT_COOKIEFILE, $self->{_SSO_COOKIEFILE});
$self->{_CH}->setopt(CURLOPT_COOKIEJAR, $self->{_SSO_COOKIEFILE});

$self->{_CH}->setopt(CURLOPT_COOKIESESSION, 1);
$self->{_CH}->setopt(CURLOPT_COOKIE,  'PERLSESSID=' . md5_hex(int(rand(99999999))));

$self->{_CH}->setopt(CURLOPT_FOLLOWLOCATION, 1);
$self->{_CH}->setopt(CURLOPT_UNRESTRICTED_AUTH, 1); # we do not really send any password, BTW.

if ($self->{_DEBUGCURL}) {
 $self->{_CH}->setopt(CURLOPT_VERBOSE,TRUE);
 } else {
 $self->{_CH}->setopt(CURLOPT_VERBOSE,FALSE);
}
$self->{_CH}->setopt(CURLOPT_HEADER,0);
$self->{_CH}->setopt(CURLINFO_HEADER_OUT,1);
$self->{_CH}->setopt(CURLOPT_TIMEOUT,10); # this should not be needed, but sometimes requests hang 'forever'
$self->{_CH}->setopt(CURLOPT_CONNECTTIMEOUT,10); # this should not be needed, but sometimes requests hang 'forever'



$self;
}

sub DESTROY {
 my($self)=@_;
 close($self->{_OUTFILE}) if ($self->{_OUTFILE});
 close($self->{_HEADFILE}) if ($self->{_HEADFILE}); 
}

sub reprocess {
 my ($self,$outf)= @_;
 my $expire=time()+CERN_SSO_COOKIE_LIFETIME;
 my @newlines;
 print STDERR "CERNSSO: Reprocessing cookie file.\n" if ($self->{_DEBUG});

 # make sure libcurl flushes cookiefile. 
 # CULROPT_COOKIELIST & "FLUSH" exists only in curl 7.17.1
 # .. but we have 7.15 on SLC5 ..
 # .. unfortunate since the next undef should be avoided ...
 #
 undef ($self->{_CH});
 
 if(open(FH, $outf)) { 
  my @lines=<FH>;

  foreach my $line (@lines) {
   if ($line =~/^${\(CERN_SSO_HTTPONLY)}(.*)/) { $line=$1."\n";}
   if ($line =~/^(.*)\s+(.*)\s+(.*)\s+(TRUE|FALSE)\s+0\s+(.*)/) {
        $line=$1."\t".$2."\t".$3."\t".$4."\t".$expire."\t".$5."\n";
      }
   push(@newlines,$line);
   }
  close(FH);
  push(@newlines,"# Modified by cern-get-sso-cookie.\n");

  if(open(FH, ">", $outf)) { 
    chmod 0600, $outf;
    foreach my $newline (@newlines) { printf FH "%s",$newline;}
    close(FH);
  } else {
    print STDERR "CERNSSO: Error operning $outf for reprocess (write).\n" if ($self->{_DEBUG});
    return(FALSE,undef,"Error opening $outf for reprocess (write).");
  } 
    
 } else {
   print STDERR "CERNSSO: Error opening $outf for reprocess (read).\n" if ($self->{_DEBUG}); 
   return(FALSE,undef,"Error opening $outf for reprocess (read).");
 } 
   return(TRUE,\@newlines,undef);
}

sub formstring {
 my($self,%formdata) = @_;
 my @form= ();
 foreach my $key (keys %formdata) {
   push (@form, $key."=".uri_escape(decode_entities($formdata{$key})));
 }
 return join('&',@form);
}

sub curl {
 my($self,$url,%formdata) = @_;
 my($info_url,$ret);

# if (!defined(%formdata)) {};
 my $formstring=$self->formstring(%formdata);
 $self->{_CH}->setopt(CURLOPT_URL,$url);
 $self->{_CH}->setopt(CURLOPT_POSTFIELDS, $formstring);
 $self->{_CH}->setopt(CURLOPT_POSTFIELDSIZE, length($formstring));
 $self->$setcurlout();
 print STDERR "CERNSSO: Requesting URL ($url" if ($self->{_DEBUG}); 
 print STDERR "/?$formstring" if ($self->{_DEBUG} && length($formstring));
 print STDERR ").\n" if ($self->{_DEBUG}); 
 $ret=$self->{_CH}->perform;
 if ($ret) {
  print STDERR "CERNSSO Error: ".$self->{_CH}->strerror($ret)." (".$self->{_CH}->errbuf.")\n" if ($self->{_DEBUGCURL});
  return (FALSE,undef,$self->{_CH}->strerror($ret)." (".$self->{_CH}->errbuf.")");
 }

 $info_url= $self->{_CH}->getinfo(CURLINFO_EFFECTIVE_URL);
 
#
# This is an error-prone way of detecting IDP:
# we rely on the fact that only IDP will use URLS containing
# CERN_SSO_CURL_ADFS_EP
#
if ( $info_url =~/${\(CERN_SSO_CURL_ADFS_EP)}/) {

  print STDERR "CERNSSO: Redirected to IDP ($info_url).\n" if ($self->{_DEBUG});
  
  $self->{_CH}->setopt(CURLOPT_URL,$info_url);
  $self->{_CH}->setopt(CURLOPT_POST,1);
  $self->$setcurlout();
  $ret=$self->{_CH}->perform;
  if ($ret) {
   print STDERR "CERNSSO Error: ".$self->{_CH}->strerror($ret)." (".$self->{_CH}->errbuf.")\n" if ($self->{_DEBUGCURL});
   return (FALSE,undef,$self->{_CH}->strerror($ret)." (".$self->{_CH}->errbuf.")");
  }
  
#
# This is very error-prone way of detecting auth error: 
# unfortunately Microsoft ADFS returns 401 (Unathorized) 
# as HTTP error code for BOTH initial auth form page and auth error page ...  
#  

  if ($self->{_OUTDATA} =~/${\(CERN_SSO_CURL_AUTHERR)}/) {
    print STDERR "Redirected to IDP Authentication error (".$self->{_CH}->getinfo(CURLINFO_EFFECTIVE_URL).")" if ($self->{_DEBUG});
    my %rethash = ('info' => $self->$getinfo(), 'header' => $self->{_HEADDATA}, 'body' => $self->{_OUTDATA});
    if ($self->{_DEBUGCURL} && $self->{_CH}->curl_errno()) {
     print STDERR "CERNSSO: Error (curl): $self->{_CH}->curl_errno() : $self->{_CH}->curl_error()\n";
    }
    return (FALSE, \%rethash);
 }  

  if ($self->{_OUTDATA} =~/form .+?action="([^"]+)"/) {
    my $url_sp=$1;
    print STDERR "CERNSSO: Redirected (via form) to SP ($url_sp)\n" if ($self->{_DEBUG});

    my @formelems;
    push @formelems, [$1,$2] while $self->{_OUTDATA} =~ /input type="hidden" name="([^"]+)" value="([^"]+)"/g;
    my @forms;

#
# Microsoft ADFS produces broken encoding in auth forms: 
# '<' and '"' are encoded as '&lt;' and '&quote;' BUT '>' is NOT encoded ... go figure ...
#

    foreach(0..$#formelems) 
       { push @forms,$formelems[$_][0]."=".uri_escape(decode_entities($formelems[$_][1]));}

    $self->{_CH}->setopt(CURLOPT_URL, $url_sp);
    $self->{_CH}->setopt(CURLOPT_POSTFIELDS, join('&',@forms));
    $self->{_CH}->setopt(CURLOPT_POSTFIELDSIZE, length(join('&',@forms)));
    $self->$setcurlout();
    $self->{_CH}->perform;

#
# Hopefully we are finally redirected to the page we wanted (unless SP failed ...)
#    
    
    print STDERR "CERNSSO: Requesting URL (".$self->{_CH}->getinfo(CURLINFO_EFFECTIVE_URL) if ($self->{_DEBUG}); 
    print STDERR "/?$formstring" if ($self->{_DEBUG} && length($formstring));
    print STDERR ").\n" if ($self->{_DEBUG}); 
    $self->{_CH}->setopt(CURLOPT_POSTFIELDS, $formstring);
    $self->{_CH}->setopt(CURLOPT_POSTFIELDSIZE, length($formstring));
    $self->$setcurlout();
    $ret=$self->{_CH}->perform;
    if ($ret) {
     print STDERR "CERNSSO Error: ".$self->{_CH}->strerror($ret)." (".$self->{_CH}->errbuf.")\n" if ($self->{_DEBUGCURL});
     return (FALSE,undef,$self->{_CH}->strerror($ret)." (".$self->{_CH}->errbuf.")");
    }

  }

 }

# segfaults in perl-WWW-Curl < 4.15: https://rt.cpan.org/Public/Bug/Display.html?id=62976 
# $self->{_CH}->getinfo(CURLINFO_PRIVATE);
 
 $self->{_CH}->close;

 my $res = TRUE;
#
# This is very error-prone way of detecting auth error:  

# still on the auth page - something went wrong.
 if($self->{_CH}->getinfo(CURLINFO_EFFECTIVE_URL) =~ /${\(CERN_SSO_CURL_ADFS_SIGNIN)}/) { $res = FALSE;}
# non-existing web site  
 if(!defined($self->{_HEADDATA}) || !defined($self->{_OUTDATA})) { $res = FALSE;}
 
 my %rethash = ('info' => $self->$getinfo(), 'header' => $self->{_HEADDATA}, 'body' => $self->{_OUTDATA});

 my $err=$self->{_CH}->strerror($ret)." (".$self->{_CH}->errbuf.")";
 
 return ($res,\%rethash,$err); 
}
1;

__END__

=pod

=head1 NAME

 WWW::CERNSSO::Auth - Perl extension interface for CERN Single Sign On Authentication

=head1 SYNOPSIS

 use WWW::CERNSSO::Auth;
 my $wget = WWW::CERNSSO::Auth->new($outfile,$krb,$nover,$cert,$key,$cacert,$capath,$verbose,$debug);
 my ($res,$out,$err) = $wget->curl($url);
 my ($res,$out,$err) = $wget->reprocess($outfile);

=head1 DOCUMENTATION

 This module provides a Perl interface to CERN Single Sign On (SSO) authentication. It provides the funcitonality to
 acquire and store in file an CERN SSO cookie. This cookie can be reused by other tools alike wget or curl to access
 CERN SSO protected pages.
 
=head1 EXAMPLES

 Acquiring SSO cookie using CERN Kerberos ticket:
 
 use strict;
 use WWW::CERNSSO::Auth;
 
 my $cookiefile='~/private/sso-cookie.txt';
 my $url='https://cern.sso.protected/site/path';
 my $usekerberos=1;
 my $sslverify=1;
 my $wget,$res,$out,$err;

 $wget = WWW::CERNSSO::Auth->new($cookiefile,$usekerberos,$sslverify);
 ($res,$out,$err) = $wget->curl($url);

 unless ($res) { print "Error authenticating to $url : $err\n"; } 
 
 # cookie reprocessing 
 ($res,$out,$err) = $wget->reprocess($cookiefile);

 unless ($res) { print "Error: $err\n"; }

 Example usage, acquiring SSO cookie using User certificate:

 use strict;
 use WWW::CERNSSO::Auth;
 
 my $cookiefile='~/private/sso-cookie.txt';
 my $url='https://cern.sso.protected/site/path';
 my $usekerberos=0;
 my $sslverify=1;
 my $usercert='~/private/usercert.pem';
 my $userkey='~/private/userkey.pem';
 my $wget,$res,$out,$err;


 $wget = WWW::CERNSSO::Auth->new($cookiefile,$usekerberos,$sslverify,$usercert,$userkey);
 ($res,$out,$err) = $wget->curl($url);

 unless ($res) { print "Error authenticating to $url : $err\n"; } 

 # cookie reprocessing 
 ($res,$out,$err) = $wget->reprocess($cookiefile);

 unless ($res) { print "Error: $err\n"; }
 
 =head1 COOKIE REPROCESSING
Underlying curl library provides cookies in a format that may not be undestood by other cookie
handling libraries, in order to create a cookiefile that can be used with other tools use:

 $wget->reprocess($cookiefile);

WARNING: current implementation basically destroys libcurl active handle, therefore subsequent
calls to $wget->curl(...) will fail, instantiate new object as a workaround, or call reprocess()
after all calls to curl() have been completed.
(this is due to libcurl 7.15 not flushing the cookie file correctly on close)

 =head1 KERBEROS

In order to use this module with Kerberos credentials a valid CERN Kerberos ticket must be acquired, for example using 'kinit'.

To check the valididty of Kerberos credentials please use 'klist'.

=head1 CERTIFICATES

In order to be used with this module user certificate / key files must be converted to specific formats. In order to do so you may:

export your certificate from web browser as myCert.p12 file (Firefox: Edit->Preferences->Advanced->Encryption->View Certificates->Your Certificates->Backup)

then use following sequence of commands in order to convert it:

openssl pkcs12 -clcerts -nokeys -in myCert.p12 -out ~/private/myCert.pem

openssl pkcs12 -nocerts -in myCert.p12 -out ~/private/myCert.tmp.key

openssl rsa -in ~/private/myCert.tmp.key -out ~/private/myCert.key

rm ~/private/myCert.tmp.key

chmod 644 ~/private/myCert.pem

chmod 400 ~/private/myCert.key

B<WARNING>: 'openssl rsa..' command removes the passphrase from the private key, please make sure your key file is stored in secure location ! 


=head1 AUTHOR

Jaroslaw Polok <Jaroslaw.Polok@cern.ch>

=head1 NOTES

CERN SSO cookies are created per web site: In order to access protected content on a given site a SSO cookie for that site must be acquired.
CERN SSO cookies expire within 24 hours.


B<WARNING>: Always store sso cookiefile in a private directory: it can be used 
by anybody to authenticate to CERN SSO as your account !
 
