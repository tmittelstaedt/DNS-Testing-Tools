Here you will find a variety of Powershell DNS testing tools.  I wrote these to take advantage of the capabilities of Powershell to make DNS queries.
While Microsoft still ships the program "nslookup" with Windows, that program has limited functionality and is considered obsolete.  The replacement
program, named "dig", for many years had a Windows command-line version maintained by the ISC.  Unfortunately, code changes in the ISC BIND distribution
would have required a large amount of effort to rewrite the Windows version of "dig" so the ISC abandonded it.

Microsoft offers 2 APIs for DNS.  The first is a Winsock API that is fairly full featured the second is a Powershell cmdlet which is less featured and
is unable to make several kinds of DNS queries.  So some of the Powershell scripts here assemble the DNS query packet manually and use the raw
UDP socket available in Powershell to send the query.

The dns-proxy-test Powershell script uses the ISC dig command and was written for the purpose of discovering transparent DNS proxies.  The Comcast ISP
that I use runs a transparent DNS proxy that caused interference when I setup a DNS server on a static IP block from Comcast.  At that time I was not
aware that Comcast ran a transparent proxy.  After this possibility was suggested on the DNS mailing list I wrote the script to verify it.  It runs
multiple tests that can identify if a transparent DNS proxy exists between the PC it is running on and the Internet.

The problem with transparent DNS proxies is that normally the customer is unaware they are there present.  The DNS system was designed to be
hierarchical and having customers set their DNS servers to IP addresses for OpenDNS and Google DNS completely defeats the purpose of the system and is
utterly unscalable, so I do understand why ISPs run these proxies which intercept DNS calls, but on the other hand the ISPs owe it to their customers
to inform them of what they are doing.  However, the customers need to stop using DNS servers that are thousands of miles away instead of the ISP's 
DNS servers.  Both sides are just as bad.  But ultimately the DNS server services on the Internet depend on trust, and fielding a proxy without telling
your customers does not create trust.

dns-proxy-test.pl                   Powershell script to detect transparent proxies

dns-proxy-test-README.html          HTML README file for the script

dns-proxy-test.html                 HTML Documentation

dns-proxy-test.MSWord-README.docx   Microsoft Word documentation on the script
