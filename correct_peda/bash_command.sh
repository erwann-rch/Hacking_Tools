cd /opt
sudo git clone https://github.com/longld/peda.git
echo "source /opt/peda/peda.py" > ~/.gdbinit
cd peda
sudo cp peda.py peda.py.old
sudo python ../correct_peda.py
sudo rm -rf lib/six.py
sudo apt install python3-six
gdb
