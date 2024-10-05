import time

# im first gonna go with the file based imports, then
# the visualization imports,

# then the ml part

# also gonna go with the system resource monitors and the time module

# also im gonna add the data manipulation modules later on in
# theri respective version to enable cuda accdleeration
time.sleep(0.2)
# ________________________________________________________________________________________________________________
print("Program has been initialized")
time.sleep(1)
print("Starting with the following imports:")
time.sleep(0.2)

import os
import pathlib

print("File monitors initialized")
time.sleep(0.2)
start_time = time.time()

# ________________________________________________________________________________________________________________

import seaborn as sns
import matplotlib.pyplot as plt

print("Visualizers enabled")
time.sleep(0.2)
# _______________________________________________________________________________________________________________

#              actually un comment the tensorflow and the keras import after production is complete as it takes a
#              lot of time to initialize
# import tensorflow

import learn
# import keras
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve, auc
from sklearn.metrics import classification_report
from sklearn.decomposition import PCA

print("Machine Learning Frameworks have been initialized")
time.sleep(0.2)
# _______________________________________________________________________________________________________________
#   System resource monitors


import psutil
import GPUtil
import speedtest
import cpuinfo
import platform
import subprocess
import capstone
import lief

print("System monitors initialized")
time.sleep(0.2)
# _______________________________________________________________________________________________________

#    Now i will be importing data analysis tools

import numpy as np
import pandas as pd
import scipy

print("Data Analysis Tools initialized")
time.sleep(0.2)
# __________________________________________________________________________________________________________

# now i will be importing cybersecurity related liobraries while classsif=ying them into
# static, dynamic and ml related domains

import pefile
import hashlib
from elftools.elf.elffile import ELFFile
import yara

print("Security Analysis tools initialized")
time.sleep(0.2)
# _____________________________________________________________________________________________________________

#  here comes the network analyzers

import scapy
import pyshark

print("Network Monitors initialized")
time.sleep(0.2)
tot = int(time.time() - start_time)
print("Total importing time: " + str((tot)) + " seconds")
time.sleep(1)
print("Imports complete")
# ________________________________________________________________________________________________________________

#  As im still looking for the perfect way to integrate our libraries, i will be looking forward to reduce the imports
#     once the modules and functions i find condense

""" 
1. i will first look into the total import size and also configure how the device hadles the stress aas all 
devices are not made in the same way

2.I will define the first base model of its workings in a modular way

           1) i will look into the system components to make sure it runs on all devices equally well 
           as a virtual box may not have generous resources allocated to it
           2) i will assign the model to systematically decide what analysis to use based on the 
             system speed, cores, performance and memory allocated to it
           3) i do expect slight challenges associated with it as i may have to look around for multiple
           systems and diversity associated with them
           4) i'm also leaving macs out of it


                    Step 1)  check the system for its various 
                             components using the python libraries.
                                    |
                                    |
                                    |
                    Step 2)  use the guidelines to initialize 
                             the processes all the while including
                              the system limitations and ends.
                                     |
                                     |
                                     |
                    Step 3)  now currently there are three features supported by our software and those are:

                        1. Quick scan
                        2. Deep scan
                        3. Real time protection with AI


                . Other than that, we also are pulling a database that will help us keep up with 
                 real time events and all that is going on currently
                 . So i better include the network and the memory with the cpu stats
                 . the real time model will most likely use less power and stay awake in the background
                   it wil fetch the stats as it pleases and stay awake for the required amount of time
                   . and i just got a new idea to add an automater program so that we wont have to initialize
                     the server and the backend seperately so that it will do it for us just like when we
                     open an app on our phone

                """

"""

I am right now determining the best power efficient and optimized way of doing things as 
iteration and scanning requires a lot of energy....considerably even more than gaming tasks

"""

"""
     I am defining the the current, maximum and minimum cpu speed
     with the number or physical and hyper threaded logical cores
     and the total power outputted with battery capacity, discharge 
     rate and the voltage supported by the battery 
"""


def current_cpu_speed():
    return psutil.cpu_freq().current


def max_cpu_speed():
    return psutil.cpu_freq().max


def min_cpu_speed():
    return psutil.cpu_freq().min


def current_cpu_usage():
    return psutil.cpu_percent(interval=1)


def num_phy_cores():
    return psutil.cpu_count(logical=False)


def num_log_cores():
    return psutil.cpu_count(logical=True)


def total_power():
    return num_phy_cores() * current_cpu_speed()


def get_battery_status():
    charging = psutil.sensors_battery().power_plugged
    return charging


def current_battery_capacity():
    return psutil.sensors_battery().percent


def get_discharge_rate():
    battery = psutil.sensors_battery()
    if battery:
        discharge_rate = battery.secsleft
        return discharge_rate if discharge_rate != psutil.POWER_TIME_UNKNOWN else 'Calculating...'
    else:
        return 'No battery information available.'


def get_battery_voltage():
    try:
        with open('/sys/class/power_supply/BAT0/voltage_now', 'r') as f:
            voltage_now = int(f.read().strip()) / 1_000_000

            return voltage_now
    except FileNotFoundError:
        return 'N/A'

    except Exception as e:
        return "error"


# the memory variable should not be tampered with

def total_ram():
    memory = psutil.virtual_memory()
    return memory.total / (1024 ** 3)


def total_available_ram():
    memory = psutil.virtual_memory()
    return memory.available / (1024 ** 3)


def used_ram():
    memory = psutil.virtual_memory()
    return memory.used / (1024 ** 3)


def ram_usage():
    memory = psutil.virtual_memory()
    return memory.percent


def iterate_files(start_directory):
    """
    the ffollowing iterates through every file in the system

    """
    for dirpath, dirnames, filenames in os.walk(start_directory):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            print(file_path)
            """i am currently going with just the namimg and later on add 
            the functions that will go through the signatures for a static analysis
            """


def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def calculate_sha1(file_path):
    sha1_hash = hashlib.sha1()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha1_hash.update(byte_block)
    return sha1_hash.hexdigest()


"""
  I just would like to make it clear that md5 hashes are not very ideal for critical security purposes as 
  they kinda suck and keep colliding with similar shit.....sorry for the jargon but this is what chatgpt said:

  Not recommended for malware detection or cryptographic purposes due to known vulnerabilities and collisions.
  Why use it? MD5 is still used in many legacy systems for basic integrity checks (e.g., file downloads) but 
  should not be trusted for security-critical purposes.

   Drawback: Malware authors can craft different files that generate the same MD5 hash (collision attack),
   making it unreliable for identifying malware.

       So im clearly hellbent on using it for quick scan kind of applications

       you clearly have the liberty to interchange the functions

"""


def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()


"""
Now i will be classifying the device based on its capabilities

"""


def deep_scan():
    """i am loading the file only when i need it to avoid unnecessary file and storage requirements
    as this is a pretty big file and i need to look through the whole file


    also i will be usi
    """

    def load_hash_file(csv_file):
        df = pd.read_csv(csv_file, header=None)
        return set(df[0])

    def check_for_malware_signature(file_hash):
        if file_hash in """add the function to the file checker""""":
            return True
        else:
            return False

    ram_use = ram_usage()
    ram = total_available_ram()
    battery_capacity = current_battery_capacity()
    cpu_usage = current_cpu_usage()
    charging = get_battery_status()

    if current_cpu_usage() < 20 and total_available_ram() >= 4 and battery_capacity >= 60 and charging == True:
        while cpu_usage < 85 and ram_use < 70:
            try:
                print("The scan has been started.....")
                print("Opening the C file")
                start_directory = "C:\\"

                print("Variable initialized")
                iterate_files(start_directory)
                print("                                SCAN COMPLETE                  ")

            except Exception as error:
                print("an error occurred while iterating files")

            else:
                print("nothing went wrong")

    else:
        print("Your System does not meet the current requirements")


def real_time_monitoring():
    return


def quick_scan():
    return

























