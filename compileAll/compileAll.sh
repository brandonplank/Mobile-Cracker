echo "Ender version number:"
read version

find . -name '.DS_Store' -delete

mkdir output
cd input

rm -rf ./Mobile\ Cracker.app/_CodeSignature
rm -f ./Mobile\ Cracker.app/embedded.mobileprovision

# make the ipa
mkdir ./Payload
cp -r ./Mobile\ Cracker.app ./Payload
zip -r ../output/org.brandonplank.mobilecracker.ipa ./Payload
rm -rf ./Payload

# make the deb
mkdir ./deb
mkdir ./deb/Applications
mkdir ./deb/DEBIAN
echo "Package: org.brandonplank.mobilecracker
Name: Mobile Cracker
Version: $version
Architecture: iphoneos-arm
Description: A password hash tool
Maintainer: Brandon Plank
Author: Brandon Plank
Section: Utilities
" >> ./deb/DEBIAN/control

cp -r ./Mobile\ Cracker.app ./deb/Applications
cp -r ../postinst ./deb/DEBIAN
cp -r ../postrm ./deb/DEBIAN
chmod 0775 ./deb/DEBIAN/postinst
chmod 0775 ./deb/DEBIAN/postrm
dpkg-deb --build ./deb ./org.brandonplank.mobilecracker.deb
mv ./org.brandonplank.mobilecracker.deb ../output
rm -rf deb
