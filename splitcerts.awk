BEGIN {
    FS="=";
    n=0;
    name="cert-" n;
}
split_after==1 {
    n++;
    split_after=0;
    write_enable=0;
    name="cert-" n;
}
/^subject/ {
    gsub(/^ +/, "", $7);
    name = $7;
    #print "///" $7 "///"
}
/-----BEGIN CERTIFICATE-----/ {
    write_enable=1;
}
/-----END CERTIFICATE-----/ {
    split_after=1;
}
write_enable==1 {
    #print name ".pem";
    print > name ".cer";
}