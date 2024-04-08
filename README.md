Kindly note that code is inherited from MJSIP 
I have added AKAv1-MD5 Auth also note that this is just basic implementation there is no multithreading implemented.

To run just create 2 files as follows 
file 1 : /tmp/userkeys
username,k,opc
111111111111111@ims.mnc001.mcc001.3gppnetwork.org,11223344556677889900aabbccddeeff,11223344556677889900aabbccddeeff

currently sqn is 1 and AMF is 8000 
if you want to test on live 4g network then u need to make sure that sqn check in sim is disabled 

if you are using osmosim then use "https://www.sysmocom.de/manuals/sysmousim-manual.pdf" 

also currently only IMSI based calling is enabled so no phone number are recognized


It really a dirty commit and may be god willing i may create better version of this.
