#!/usr/bin/env bash

# For yes/no prompt, and line breaks
# get it at gitlab.com/artnoi-staple/unix/sh-tools/bin/yn.sh

. "$(command -v yn.sh)";
. "$(command -v lb.sh)";

typeset -A name flag ext;

# If you dont want to run certain test functions,
# just prepend a comment (#) OR remove the 'function' keyword

# Tests will be run from top to bottom

function gcm_key() {
	name[gcm_key]='AES GCM (with keyfile)';
	flag[gcm_key]="-k";
	ext[gcm_key]='.gcm.wkey';
}
function gcm_hex_key() {
	name[gcm_hex_key]='AES GCM (hex with keyfile)';
	flag[gcm_hex_key]="-H -k";
	ext[gcm_hex_key]='.gcm.hex.wkey';
}
function gcm_b64_key() {
	name[gcm_b64_key]='AES GCM (Base64 with keyfile)';
	flag[gcm_b64_key]="-B -k";
	ext[gcm_b64_key]='.gcm.b64.wkey';
}
function ctr_key() {
	name[ctr_key]='AES CTR (with keyfile)';
	flag[ctr_key]="-m CTR -k";
	ext[ctr_key]+='.ctr.wkey';
}
function ctr_hex_key() {
	name[ctr_hex_key]='AES CTR (hex with keyfile)';
	flag[ctr_hex_key]="-m CTR -H -k";
	ext[ctr_hex_key]+='.ctr.hex.wkey';
}
function ctr_b64_key() {
	name[ctr_b64_key]='AES CTR (Base64 with keyfile)';
	flag[ctr_b64_key]="-m CTR -B -k";
	ext[ctr_b64_key]+='.ctr.b64.wkey';
}
function gcm() {
	name[gcm]='AES GCM (passphrase)';
	flag[gcm]="";
	ext[gcm]='.gcm';
}
function gcm_hex() {
	name[gcm_hex]='AES GCM (hex with passphrase)';
	flag[gcm_hex]="-H";
	ext[gcm_hex]='.gcm.hex';
}
function gcm_b64() {
	name[gcm_b64]='AES GCM (Base64 with passphrase)';
	flag[gcm_b64]="-B";
	ext[gcm_b64]='.gcm.b64';
}
function ctr() {
	name[ctr]='AES CTR (passphrase)';
	flag[ctr]="-m CTR";
	ext[ctr]+='.ctr';
}
function ctr_hex() {
	name[ctr_hex]='AES CTR (hex with passphrase)';
	flag[ctr_hex]="-m CTR -H";
	ext[ctr_hex]+='.ctr.hex';
}
function ctr_b64() {
	name[ctr_b64]='AES CTR (Base64 with passphrase)';
	flag[ctr_b64]="-m CTR -B";
	ext[ctr_b64]+='.ctr.b64';
}

if [[ -x gfc && ! -d gfc ]];
	then
	printf "WARN: Testing built binary not source\n";
	printf "To test source, remove file named 'gfc'\n";

	gfccmd='./gfc';
else
	gfccmd="go run main.go";
fi;

encsrc='files/zeroes';
encdst0='/tmp/testgfc';
decdst0='/tmp/zeroes';

simyn "Run test RSA on file files/aes.key with keys files/pub.pem and files/pri.pem?"\
&& pub="files/pub.pem"\
&& pri="files/pri.pem"\
&& printf "Testing RSA encryption (ENV)\n"\
&& [[ -f $pub || -f $pri ]]\
&& RSA_PUB_KEY=$(< $pub) go run main.go -rsa -i files/aes.key -o /tmp/rsaOut\
&& printf "Testing RSA decryption (ENV)\n"\
&& RSA_PRI_KEY=$(< $pri) go run main.go -rsa -d -i /tmp/rsaOut -o /tmp/aes.key\
&& printf "Testing equality\n"\
&& diff /tmp/aes.key files/aes.key\
&& printf "✅ (ok) files match\n"\
&& go run main.go -rsa -k -pub $pub -i files/aes.key -o /tmp/rsaOut\
&& printf "Testing RSA decryption\n"\
&& go run main.go -rsa -d -k -pri $pri -i /tmp/rsaOut -o /tmp/aes.key\
&& printf "Testing equality\n"\
&& diff /tmp/aes.key files/aes.key\
&& printf "✅ (ok) files match\n"\
&& rm /tmp/rsaOut /tmp/aes.key\
|| printf "❌ (failed) files differ";

line;

# Get function names of this file from awk
functions=$(awk '/^function / {print substr($2, 1, length($2)-2)}' $0);

c=0 && for fun in ${functions[@]};
do
	((c++));

	"$fun"\
	&& name="${name[$fun]}"\
	&& encdst="${encdst0}${ext[$fun]}"\
	&& decsrc="${encdst}"\
	&& decdst="${decdst0}${ext[$fun]}"\
	&& alflag="${flag[$fun]}";
	
	simyn "\nRun test ${c} - ${name[$fun]}"\
	|| continue;

	# Encrypt, decrypt, and check diff
	sh -c "${gfccmd} -i ${encsrc} -o ${encdst} ${alflag}";
	sh -c "${gfccmd} -i ${decsrc} -o ${decdst} ${alflag} -d";
	diff $decdst $encsrc\
	&& printf "\n✅ (ok) files match:\n${decdst} == ${encdst}\n"\
	|| printf "\n❌ (failed) files differ:\n${decdst} xx ${encdst}\n";
	simyn "Finished test ${name}.\nRemove test files?"\
	&& rm -v "$encdst" "$decdst";
	line;
done;

simyn "All tests done. Remove all test files?"\
&& rm -v "$encdst0"* "$decdst0"*;