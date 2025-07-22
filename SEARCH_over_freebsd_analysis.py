import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
import numpy as np
import re
import pandas as pd
import os
import bisect
from scipy.stats import rankdata
from scipy.interpolate import interp1d

SEARCH_RESULT = True

cwd = os.getcwd()
base_path = "/Users/rezasaadati/SEARCHTest/data/freebsd_search_on/server_freebsd_client_glomma/"

fig_path = "/Users/rezasaadati/SEARCHTest/data/freebsd_search_on/server_freebsd_client_glomma/figures/"
os.makedirs(fig_path, exist_ok=True)

FOLDER_PATH = "data/log_off"

############################### Functions #########################################
###################################### SEARCH ##############################################################
if SEARCH_RESULT:

    
    folder_path = os.path.join(base_path, FOLDER_PATH)

    if os.path.isdir(folder_path):
        print("Processing:", folder_path)
        # count the number of files in the directory
        num_files = len([name for name in os.listdir(folder_path) if name.endswith(".csv")])

        SERVER_IP = "130.215.28.249"
        INTERVAL = 0.025

        first_loss_time_list = []
        early_loss_counter = 0
        donot_exist_counter = 0

        for num in range(num_files+1):
            data_path = os.path.join(folder_path, f"log_data{num+1}.csv")

            if not os.path.exists(data_path):
                print(f"File {data_path} does not exist")
                continue
                   
            print(f"Processing file: log_data{num+1}.csv")

            # read csv_log file
            df = pd.read_csv(data_path)                

            first_time_loss = df['now_s_loss'].iloc[0] if not df['now_s_loss'].isnull().all() else None
            first_loss_time_list.append(first_time_loss)

            if first_time_loss is not None and first_time_loss <= 10:
                early_loss_counter += 1
            if first_time_loss is None:
                donot_exist_counter += 1

        # find cdf of first_loss_time
        first_loss_time_list = [time for time in first_loss_time_list if time is not None]
        first_loss_time_list.sort()
        first_loss_time_list = np.array(first_loss_time_list)
        # Calculate CDF
        cdf = np.arange(1, len(first_loss_time_list) + 1) / len(first_loss_time_list)
        # Plot CDF
        plt.figure(figsize=(8, 6))
        plt.plot(first_loss_time_list, cdf, marker='o', linestyle='--', color='blue')
        plt.title("CDF of First Loss Time")
        plt.xlabel("First Loss Time (s)")
        plt.ylabel("CDF")
        plt.axvline(x=10, color='red', linestyle='--', label='10s')
        plt.legend()
        plt.savefig(os.path.join(fig_path, "CDF_first_loss_time.png"))
        plt.close()

        # make a table shows the percentage of early loss
        early_loss_num = early_loss_counter 
        donot_exist_num = donot_exist_counter

        plt.figure(figsize=(5, 5))
        plt.pie([early_loss_num, donot_exist_num, num_files - early_loss_num - donot_exist_num],
        labels=['Early Loss', 'No Loss', 'Loss > 10s'],
        autopct='%1.1f%%')
        # plt.title("Samples with Same exit_time Across Alphas[1 4]")
        plt.savefig(os.path.join(fig_path, "same_exit_time_across_all_alphas.png"))
        plt.close()


            