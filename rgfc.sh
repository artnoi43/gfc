#!/bin/bash
tarballe="/tmp/$1.zstd.tar";
tarballd="$2.zstd.tar";
gfcout="$tarballe.gfc.out";

# tar and encrypt
if [ "$1" != '-d' ];
then
	if [ -d "$1" ];
	then
		# GNU tar only, for BSD tar, use -cJf instead (xz)
		tar --zstd -cf "$tarballe" "$1"\
		&& gfc -i "$tarballe" -o "$gfcout"\
		&& rm -v "$tarballe"\
		&& printf "Wrote to $gfcout\n"
	else
		printf "error: Expecting directory\nIf you are decrypting a file, use -d flag";
	fi;
elif [ -n "$2" ];
then
# untar and decrypt
	printf "%s\n" "Will decrypt and untar {$2} in $(pwd)"
	gfc -d -i "$2" -o $tarballd\
	&& tar -xf "$tarballd"\
	&& rm -v $tarballd;
fi
