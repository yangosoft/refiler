# refiler #

Supose you started a process redirecting stdout to _/dev/null_ but now you want to read stdout. With refiler you can open a new file descriptor on this process then call to dup2 and finally you obtain stdout (or whatever fd) redirected. You can change a file descriptor "on the fly" without stopping that process.

refiler is completely based on rptyr from Nelson Elhage <nelhage@nelhage.com> https://github.com/nelhage/reptyr

You can achieve the same with this script and gdb: http://users.linpro.no/ingvar/fdswap.sh.txt


## Usage ##
$./refiler PID file-descriptor-to-redirect new-file
Example:
./refiler 10250 1 /tmp/stdout-from-10250