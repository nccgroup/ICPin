# ICPin #
#### An Integrity-Check Monitoring Pintool ####

### What ###
A pintool that records the reads and writes to the executable in memory. It
also tracks dynamically executed code and handles some antidebug checks (it is
immune to most antidebug by pintool`s design) and outputs backtraces of watched
behavior.

### How ###
#### Building ####
* Download MSCV version from https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads
* Open MyPinTool.sln in Visual Studio
* Adjust the include and link directories to match your pintool install location
* Build the solution

#### Running ####
`pin -t path/to/ICPin.dll -- /path/to/target/executable`

### References ###
https://software.intel.com/sites/landingpage/pintool/docs/81205/Pin/html/
