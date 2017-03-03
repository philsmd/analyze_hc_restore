# About

The goal of this project is to make the content of a hashcat .restore file human-readable.  
  
The format of these files is defined here: https://hashcat.net/wiki/restore

# Requirements

Software:  
- Perl must be installed (should work on *nix and windows with perl installed)


# Installation and First Steps

* Clone this repository:  
    git clone https://github.com/philsmd/analyze_hc_restore.git  
* Enter the repository root folder:  
    cd analyze_hc_restore
* Run it:  
    ./analyze_hc_restore.pl hashcat.restore
* Check output

# Usage and command line options

A very interesting feature of this tool is, that it is able to modify .restore files (besides making them human-readable).  
  
To list the OPTIONS available use:  
    ./analyze_hc_restore.pl --help

# Hacking

* More features
* CLEANUP the code, use more coding standards, make it easier readable, everything is welcome (submit patches!)
* all bug fixes are welcome
* testing with different .restore files and/or write tests
* solve and remove the TODOs (if any exist)
* and,and,and

# Credits and Contributors 
Credits go to:  
  
* philsmd, hashcat project

# License/Disclaimer

License: belongs to the PUBLIC DOMAIN, donated to hashcat, credits MUST go to hashcat and philsmd for their hard work. Thx  
  
Disclaimer: WE PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE Furthermore, NO GUARANTEES THAT IT WORKS FOR YOU AND WORKS CORRECTLY
