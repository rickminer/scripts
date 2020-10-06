#!/bin/bash
# Video commands
# Set Tape number var
last_dir=$(ls -d tape*/ | sort -Vr | head -1)
num1=${last_dir#tape}
num2=${num1:0:2}
num3=${num2##+(0)}
num4=$((10#$num3))
tape=tape$(printf %02d $(($num4+1)))
echo "Making $tape..."
# Make tape folder
mkdir $tape
# Grab raw video
dvgrab --autosplit --timestamp --size 0 --rewind $tape-
# status of last command
if [ ! $? -eq 0 ]; then
    echo "[ERROR]        dvgrab failed!"
    exit 1;
fi
# Convert video files
for file in $tape*.dv; do
    HandBrakeCLI -i $file -o ${file%.dv}.m4v --preset="HQ 720p30 Surround"
    # Exit if there is an erro
    if [ ! $? -eq 0 ]; then
        echo "[ERROR]        HandBrakeCLI had an error!"
        echo $file
        exit 2;
    fi
done
# Move video files
mv $tape*.dv $tape/
# Fix timestamps
for file in $tape*.m4v; do 
    ts=$(basename "$file" .m4v | sed -e 's/^tape[0-9][0-9]-//g' -e 's/[-._]//g')
    touch -mat ${ts%[0-9][0-9]} $file
    exiftool -overwrite_original -preserve '-AllDates<FileModifyDate' $file
done
# Move mp4 files
mv $tape*.m4v m4v/
# print drive stats
df -h /mnt/sda1
du -h /mnt/sda1

# In powershell and in temp directory, then move to folder.
# cd E:\Temp
# Get-ChildItem *.m4v | % { $_.CreationTime=$_.LastWriteTime }
# Get-ChildItem tape* -Force | Select-Object FullName, CreationTime, LastAccessTime, LastWriteTime, Mode, Length
# Move-Item *.m4v E:\Videos\Camcorder