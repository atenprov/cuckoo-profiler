#!/usr/bin/env python
#    
#  Profiler - Automated malware profilling through the correlation of Cuckoo Sandbox Malware Analysis Results
#
#  Copyright (C) 2013  Profiler Team.
# 
#  This file is part of Profiler.
# 
#  Profiler is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
# 
#  Profiler is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see http://www.gnu.org/licenses/

import os
import sys
import sqlite3
import json
from copy import deepcopy
import pickle
from collections import defaultdict
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.mlab as mlab
from utils import File
import base64

#connect to cuckoo database
conn = sqlite3.connect('cuckoo.db')
c = conn.cursor()

try:
    from pymongo.connection import Connection
    from pymongo.errors import ConnectionFailure
except ImportError:
    raise CuckooDependencyError("Unable to import pymongo")

c.execute('SELECT * FROM tasks')
#search for unique md5
md5_list = []

for row in c:
    if row[1] not in md5_list:
        md5_list.append(row[1])
     
try:
    connection = Connection()
except ConnectionFailure:
            print "Cannot connect to MongoDB"

db = connection.cuckoo

# create profiles folder
profiles_folder = "profiles"
if not os.path.exists(profiles_folder):
    os.mkdir(profiles_folder)
    
# process each different malware sample
for r in md5_list:
    print "Processing the analyses results of ", r
    print "Please Wait...." 
    results_dict = {}
    results_dict["mongo_id"] = []
    temp_res = []
    temp_dict = {}
    temp_one = {}
    temp_profile = {}
    results_dict["api_summary"] = {}
    
    #check if malware profile already exists
    temp_profile = deepcopy(db.profiles.find_one({"malware_info.md5" : r})) 
    
    #find all the analysis results for the given malware
    cur = db.analysis.find({"file.md5" : r })
    temp_dict = db.analysis.find_one({"file.md5" : { "$in": [r] } } , {"dropped" : 1})
    temp_one = db.analysis.find_one({"file.md5" : r}) 

    total = db.analysis.find({"file.md5" : r } , {"dropped" : 1}).count()
    
    # if profile exists pass it on to a temporary container in order to compare new analysis results with current profile
    if temp_profile:
        profile = deepcopy(temp_profile)
        temp_profile_id = db.profiles.find({"md5_id" : r})[0][u"_id"]    
        network = deepcopy(temp_profile["results"]["network"])
        behavior = deepcopy(temp_profile["results"]["behavior"])
        summary = deepcopy(temp_profile["results"]["behavior"]["summary"])
        dropped_files = deepcopy(temp_profile["results"]["dropped"])
        results_dict = deepcopy(temp_profile["results"])
        executions_summary = deepcopy(temp_profile["executions_summary"])
    
    #otherwise create new profile
    else:
        profile = {}
        dropped_files = []
        network = {}
        network["udp"] = []
        network["hosts"] = []
        network["dns"] = []
        behavior = {}
        behavior["processes"] = []   
        behavior["processtree"] = []
        summary = {}
        summary["files"] = []
        summary["keys"] = []
        summary["mutexes"] = [] 
        behavior["summary"] = deepcopy(summary)
        results_dict = {}
        results_dict["mongo_id"] = [] 
        executions_summary = []
        results_dict["api_summary"] = {}

# initialize temp values
    analysis = []  
    network_hosts = []
    network2 = []
    udps = []    
    udp_value = {}
    hosts_value = {}
    temp_value = {}          
    process_calls = {}
    process_calls["calls"] = []
    calls = []
    lencalls = []   
    executions = {}   
    processes = []       
    simm_diff = {}
    simm_diff["simmilar"] = {}
    simm_diff["different"] = {} 
    count_res = 0
    count_dropped_simm = 0 
    count_repeated_files = 0  
    api_names_summary = []
    analysis_apis = {}
    api_names = []

    #for each analysis result
    for res in cur:

        #create profile results directories
        profile_path = os.path.join(profiles_folder, r)
        if not os.path.exists(profile_path):
            os.mkdir(profile_path)
        #create charts subfolder            
        charts_path = os.path.join(profile_path, "charts")
        if not os.path.exists(charts_path):
            os.mkdir(charts_path)    

        #process only new analysis results
        #this is done by storing the analysis mongo id within the profile container
        #if the analysis id exists within the profile move on, otherwise process the results and append the new analysis id
        indic_id = 0
        for k,v in res.iteritems():
            if k not in results_dict and k != "_id":
                results_dict.setdefault(k,[])
                simm_diff["simmilar"].setdefault(k,[])
                simm_diff["different"].setdefault(k,[])
            found_id = False          
            if (not found_id and indic_id == 0):
                for value in results_dict["mongo_id"]:
                    if res["_id"] == value:
                        found_id = True                                               
                        break;
                    else:
                        found_id = False     

            if (not found_id and indic_id == 0): 
                results_dict["mongo_id"].append(res["_id"])                                        
              
            if not found_id: 
                indic_id = 1
                # find dropped files duplicates                                                       
                if k == "dropped":
                    #for each dropped file whithin the current analysis results 
                    for dropped in res["dropped"]:
                        found = False
                        found_name = False
                        found_size = False
                        
                        #check if the file exists in the profile (results_dict)
                        for i in range(0,len(results_dict["dropped"])):
                            if dropped["md5"] == results_dict["dropped"][i]["md5"]:  
                                  found = True
                                  pos = i
                                  if dropped["name"] == results_dict["dropped"][i]["name"]:
                                       found_name = True
                                  if dropped["size"] == results_dict["dropped"][i]["size"]:  
                                       found_size = True                                                            
                                  break;
                                  
                        #if the file doesn't exist then add it in the profile keeping also
                        #the analysis id were it was found
                        #otherwise check if it was dropped with a different name and keep
                        #the analysis id                                                     
                        if not found:
                            temp_value = {}                       
                            temp_value = deepcopy(dropped)
                            analysis = []
                            analysis.append(res["_id"])
                            temp_value["analysis"]=analysis
                            temp_value["repeated"] = 0
                            temp_value["all_execs"] = "No"
                            if len(temp_value["analysis"]) == total:
                                temp_value["all_execs"] = "Yes"  
                            temp_value["same_as"] =[]                      
                            results_dict["dropped"].append(temp_value)    
                        else:
                            if res["_id"] not in results_dict["dropped"][pos]["analysis"]:
                                results_dict["dropped"][pos]["analysis"].append(res["_id"])
                                if not found_name:
                                    same_as = {}
                                    same_as["name"] = dropped["name"]
                                    same_as["in_analysis"] = res["_id"]
                                    results_dict["dropped"][pos]["same_as"].append(same_as)
                            else:
                                results_dict["dropped"][pos]["repeated"] += 1
                                count_repeated_files += 1
                            if len(results_dict["dropped"][pos]["analysis"]) == total:
                                results_dict["dropped"][pos]["all_execs"] = "Yes" 
                                count_dropped_simm +=1                        

# find summary duplicates                        
                if k == "behavior":
                    for key in res["behavior"]:                            
                        if key == "summary":
                            for sumkey in res["behavior"]["summary"]:                             
                                if sumkey == "files" or sumkey == "keys" or sumkey == "mutexes": 
                                    for value in res["behavior"]["summary"][sumkey]:                                                 
                                        if sumkey == "keys" or sumkey == "mutexes":
                                            subkey = "name"
                                        else:
                                            subkey = "path"                        
                                        found = False
                                        i=0
                                        while (not found) and (i in range(0,len(summary[sumkey]))):         
                                            if value == summary[sumkey][i][subkey]:                                      
                                                found = True
                                                pos = i
                                            i += 1
                                        if not found:
                                            temp_value = {}                                        
                                            temp_value[subkey] = value
                                            analysis = []
                                            analysis.append(res["_id"])
                                            temp_value["analysis"]=analysis
                                            temp_value["all_execs"] = "No"
                                            if len(temp_value["analysis"]) == total:
                                                temp_value["all_execs"] = "Yes"
                                            summary[sumkey].append(temp_value)
                                        else:
                                            if res["_id"] not in summary[sumkey][pos]["analysis"]:
                                                summary[sumkey][pos]["analysis"].append(res["_id"])
                                            if len(summary[sumkey][pos]["analysis"]) == total:
                                                summary[sumkey][pos]["all_execs"] = "Yes"
                                            else:
                                                summary[sumkey][pos]["all_execs"] = "No" 
# find processes duplicates
                        if key == "processes":
                            for value in res["behavior"]["processes"]:
                                found = False
                                i=0                                                                    
                                while (not found) and (i in range(0,len(behavior["processes"]))):        
                                    if value["process_name"] == behavior["processes"][i]["process_name"]:
                                        found = True
                                        pos = i 
                                    # find call duplicates for each process                                       
                                        countfound = 0
                                        for call in value["calls"]:                                        
                                            found_call = False
                                            same_status = False
                                            same_repeated = False 
                                            found_name = False  
                                            same_args = False  
                                            same_return = False
                                            diff_status = False 
                                            diff_repeated = False                                  
                                            j=0
                                            for j in range(0,len(behavior["processes"][pos]["calls"])):
                                                # find calls with different status and repeates
                                                if call["api"] == behavior["processes"][pos]["calls"][j]["api"]:
                                                    found_name = True
                                                    pos_call = j  
                                                    if call["category"] == behavior["processes"][pos]["calls"][j]["category"]:
                                                        if call["status"] == behavior["processes"][pos]["calls"][j]["status"]:
                                                            same_status = True
                                                        if call["return"] == behavior["processes"][pos]["calls"][j]["return"]:
                                                            same_return = True
                                                        if call["repeated"] == behavior["processes"][pos]["calls"][j]["repeated"]:
                                                            same_repeated = True
                                                        if call["arguments"] == behavior["processes"][pos]["calls"][j]["arguments"]:
                                                            same_args = True
                                                        if same_status and same_return and same_repeated and same_args:
                                                            found_call = True
                                                            pos_call = j
                                                            countfound +=1
                                                            break;
                                                        else:
                                                            if not same_status and same_return and same_repeated and same_args:
                                                                diff_status = True
                                                                pos_status = j
                                                                break;
                                                            elif not same_repeated and same_return and same_status and same_args:
                                                                diff_repeated = True
                                                                pos_rep = j
                                                                break;  
                                    
                                            if not found_call:
                                                if diff_status:
                                                    behavior["processes"][pos]["calls"][pos_status]["diff_status_in"].append(res["_id"])
                                                    if res["_id"] not in behavior["processes"][pos]["calls"][pos_status]["analysis"]:
                                                        behavior["processes"][pos]["calls"][pos_status]["analysis"].append(res["_id"]) 
                                                elif diff_repeated:
                                                    diff_reps = {}
                                                    #diff_reps["repeated"] = behavior["processes"][pos]["calls"][pos_rep]["repeated"]
                                                    diff_reps["repeated"] = call["repeated"]
                                                    diff_reps["in_analysis"] = res["_id"]
                                                    behavior["processes"][pos]["calls"][pos_rep]["diff_repetitions_in"].append(diff_reps)
                                                    if res["_id"] not in behavior["processes"][pos]["calls"][pos_rep]["analysis"]:
                                                        behavior["processes"][pos]["calls"][pos_rep]["analysis"].append(res["_id"]) 
                                                else:    
                                                    call_value = {}
                                                    call_value = deepcopy(call)                                                         
                                                    analysis = []
                                                    analysis.append(res["_id"])
                                                    call_value["analysis"]=analysis
                                                    call_value["diff_status_in"] = [] 
                                                    call_value["diff_repetitions_in"] = []                                           
                                                    behavior["processes"][pos]["calls"].append(call_value)                                  
                                            else:
                                                if res["_id"] not in behavior["processes"][pos]["calls"][pos_call]["analysis"]:
                                                    behavior["processes"][pos]["calls"][pos_call]["analysis"].append(res["_id"])
                                                
                                    i += 1                                                                                          
                                if not found: 
                                    temp_value = {}                       
                                    temp_value = deepcopy(value)                                                                
                                    analysis = []
                                    analysis.append(res["_id"])
                                    for call in temp_value["calls"]:
                                        call["analysis"] = analysis
                                        call["diff_status_in"] = [] 
                                        call["diff_repetitions_in"] = []                                     
                                    temp_value["analysis"]=analysis
                                    behavior["processes"].append(temp_value)
                                else:
                                    if res["_id"] not in behavior["processes"][pos]["analysis"]:
                                        behavior["processes"][pos]["analysis"].append(res["_id"])
# find network duplicates  
                if k == "network" and res["network"]:
                    for key in res["network"]:
                        if key not in network:
                            network.setdefault(key,[])                  
                        if key == "udp": 
                            for value in res["network"]["udp"]:                                                      
                                found = False
                                i=0
                                while (not found) and (i in range(0,len(network["udp"]))):        
                                    if value["dport"] == network["udp"][i]["dport"] and \
                                       value["src"] == network["udp"][i]["src"] and \
                                       value["dst"] == network["udp"][i]["dst"] and \
                                       value["sport"] == network["udp"][i]["sport"]:
                                        found = True
                                        pos = i
                                    i += 1
                                if not found:
                                    udp_value = {}                       
                                    udp_value = deepcopy(value)
                                    analysis = []
                                    analysis.append(res["_id"])
                                    udp_value["analysis"]=analysis                                
                                    network["udp"].append(udp_value)
                                else:
                                    if res["_id"] not in network["udp"][pos]["analysis"]:
                                        network["udp"][pos]["analysis"].append(res["_id"])
                        if key == "hosts": 
                            for value in res["network"]["hosts"]:                                       
                                found = False
                                i=0
                                while (not found) and (i in range(0,len(network["hosts"]))):         
                                    if value == network["hosts"][i]["host"]:                                      
                                        found = True
                                        pos = i
                                    i += 1
                                if not found:
                                    hosts_value = {}
                                    hosts_value["host"] = value
                                    analysis = []
                                    analysis.append(res["_id"])
                                    hosts_value["analysis"]=analysis
                                    network["hosts"].append(hosts_value)
                                else:
                                    if res["_id"] not in network["hosts"][pos]["analysis"]:
                                        network["hosts"][pos]["analysis"].append(res["_id"])   
                        if key == "dns": 
                            for value in res["network"]["dns"]:                                      
                                found = False
                                i=0
                                while (not found) and (i in range(0,len(network["dns"]))):         
                                    if value["ip"] == network["dns"][i]["ip"] and \
                                       value["hostname"] == network["dns"][i]["hostname"]:                                    
                                        found = True
                                        pos = i
                                    i += 1
                                if not found:
                                    temp_value = {}
                                    temp_value = deepcopy(value)
                                    analysis = []
                                    analysis.append(res["_id"])
                                    temp_value["analysis"]=analysis
                                    network["dns"].append(temp_value)
                                else:
                                    if res["_id"] not in network["dns"][pos]["analysis"]:
                                        network["dns"][pos]["analysis"].append(res["_id"]) 
                        if key == "http": 
                            for value in res["network"]["http"]:                                                    
                                found = False
                                i=0
                                while (not found) and (i in range(0,len(network["http"]))):         
                                    if value["body"] == network["http"][i]["body"] and \
                                       value["uri"] == network["http"][i]["uri"] and \
                                       value["method"] == network["http"][i]["method"] and \
                                       value["host"] == network["http"][i]["host"] and \
                                       value["path"] == network["http"][i]["path"] and \
                                       value["data"] == network["http"][i]["data"] and \
                                       value["port"] == network["http"][i]["port"]: 
                                        found = True
                                        pos = i
                                    i += 1
                                if not found:
                                    temp_value = {}
                                    temp_value = deepcopy(value)
                                    analysis = []
                                    analysis.append(res["_id"])
                                    temp_value["analysis"]=analysis
                                    network["http"].append(temp_value)
                                else:
                                    if res["_id"] not in network["http"][pos]["analysis"]:
                                        network["http"][pos]["analysis"].append(res["_id"])  
                        if key == "tcp": 
                            for value in res["network"]["tcp"]:                                                    
                                found = False
                                i=0
                                while (not found) and (i in range(0,len(network["tcp"]))):         
                                    if value["dport"] == network["tcp"][i]["dport"] and \
                                       value["src"] == network["tcp"][i]["src"] and \
                                       value["dst"] == network["tcp"][i]["dst"] and \
                                       value["sport"] == network["tcp"][i]["sport"]:
                                        found = True
                                        pos = i
                                    i += 1
                                if not found:
                                    temp_value = {}
                                    temp_value = deepcopy(value)
                                    analysis = []
                                    analysis.append(res["_id"])
                                    temp_value["analysis"]=analysis
                                    network["tcp"].append(temp_value)
                                else:
                                    if res["_id"] not in network["tcp"][pos]["analysis"]:
                                        network["tcp"][pos]["analysis"].append(res["_id"])              
  
        if indic_id == 1:
            count_res += 1
            executions = {}
            executions["api_calls"] = {}
            executions["exec_id"] = res["_id"]
            executions["analysis_info"] = res["info"]
            executions["total_dropped_files"] = len(res["dropped"])
            executions["total_processes"] = len(res["behavior"]["processes"]) 
          
            for proc in res["behavior"]["processes"]:
                temp_process_name = proc["process_name"].rsplit('.', 1) #take the first part of the process name as key
                proc_name = temp_process_name[0]
                executions["api_calls"][proc_name] = len(proc["calls"])
              
            # Create Api Charts per analysis and process
                analysis_apis = {}
                api_names = []
            #first count apis in each process per api name
                for call in proc["calls"]:            
                    if call["api"] not in analysis_apis:
                        analysis_apis.setdefault(call["api"],0)
                        api_names.append(call["api"])
                    analysis_apis[call["api"]] +=1                   
             
            # then create bar chart
                        
                N = len( analysis_apis )
                x = np.arange(1, N+1)
                y = []
                labels = []
                for key in analysis_apis:
                    y.append(analysis_apis[key])
                    labels.append(key)   

                width = 1
                bar1 = plt.bar( x, y, width, color="g" )
                plt.ylabel( 'Occurances', fontsize=10 )
                plt.xlabel( '*Total Calls %d' %len(proc["calls"]), fontsize=8, fontstyle='italic' )
                plt.yticks.fontsize=10          
                plt.xticks(x + width/2.0, labels, rotation='vertical', fontsize=10 )            
            # anotate points
                def autolabel(bar1):
            # attach some text labels
                    for bar in bar1:
                       height = bar.get_height()
                       plt.text(bar.get_x()+bar.get_width()/2., 1.02*height, '%d'%int(height),
                               ha='center', va='bottom', fontsize=10, fontstyle='italic')

                autolabel(bar1)

            # Save to charts folder
            # the name is based on the analysis ID 
            # so first split the analysis path
   
                if "analysis_path" not in res["info"]:
                    analysis_id = str( res["_id"])
                else:
                    temp_id = res["info"]["analysis_path"].rsplit('/', 1)
                    analysis_id = temp_id[1]

                temp_proc_name = proc["process_name"].rsplit('.', 1)
                plt.title('Calls made by the %s process in analysis ID %s' %(proc["process_name"], analysis_id), 
                                                fontsize=10, fontweight = 'bold',fontstyle ='italic')
                plt.tight_layout()
          
                figapi_file_name = "api_calls_" + temp_proc_name[0] + "_"+analysis_id +".png"
                figapi_path = os.path.join(charts_path, figapi_file_name)
                plt.savefig(figapi_path, dpi=128)
            
            # Clean chart data for next process
                plt.figure()           
          
            #create summary list of apis and number of calls correlating all analyses           
            
                for api in analysis_apis:            
                    if api not in results_dict["api_summary"]:
                        results_dict["api_summary"].setdefault(api,[]) 
                        api_names_summary.append(api)                  
                    results_dict["api_summary"][api].append(analysis_apis[api])
      
            executions_summary.append(executions)


# Only if there are new analysis results continue
    if count_res > 0:   
	# after malware analyses corelation, create summary api chart and histogram
        # first compute mean and standard deviation
        api_means = {}
        api_stds = {}     
        
        for api in results_dict["api_summary"]:
            api_means[api] = np.mean(results_dict["api_summary"][api])
            api_stds[api] = np.std(results_dict["api_summary"][api])

        #Then create summary chart with mean and std
        N = len( results_dict["api_summary"] )
        x = np.arange(N)
        means = []
        stds = []    
        labels = []
        for key in results_dict["api_summary"]:
            means.append(api_means[key])
            stds.append(api_stds[key])        
            labels.append(key)  

        ind = np.arange(N)  # the x locations for the groups
        width = 0.60       # the width of the bars
	    
        if len(results_dict["api_summary"]) > 0: 
            bar1 = plt.bar(ind, means, width,
                            color='r',
                            yerr=stds)

        # add labels
            plt.ylabel('Mean Value', fontsize=10)
            plt.title('Apis Means and std for malware %s ' %(res["file"]["name"]), 
                                   fontsize=10, fontweight = 'bold',fontstyle ='italic')
            plt.xticks(x + width/2.0, labels, rotation='vertical', fontsize=10 ) 
            plt.yticks.fontsize=10  

	# anotate points
            def autolabel(bars):
        # attach some text labels
                for bar in bars:
                    height = bar.get_height()
                    plt.text(bar.get_x()+bar.get_width()/2., 1.02*height, '%d'%int(height),
                            ha='center', va='bottom', fontsize=10, fontstyle='italic')

            autolabel(bar1)

            plt.tight_layout()
        #save chart to charts path      
            summaryapi_file_name = r+".png"
            summaryapi_path = os.path.join(charts_path, summaryapi_file_name)
            plt.savefig(summaryapi_path, dpi=128)
             
        # Clean chart data for next process
            plt.figure()
        
        results_dict["network"] = network
        results_dict["signatures"] = res["signatures"]
        results_dict["file"] = res["file"]
        results_dict["static"] = res["static"]
        behavior["summary"] = summary
        results_dict["behavior"] = behavior 
                
        #update profile 
        profile.update({"md5_id":r,"total_executions":total,"malware_info":res["file"],"executions_summary":executions_summary,"results":results_dict})
        
        #save results to mongo database
        db.profiles.save(profile)
        
	#create json report 
        json_file_name = "profile_"+ r +".json"	   
        json_path = os.path.join(profile_path, json_file_name) 
        try:
            report = open(json_path, "w")
            report.write(json.dumps(profile, sort_keys=False, indent=4, default=str))
            report.close()
        except TypeError:
            print "failed to generate json report 1"
        except IOError:
            print "failed to generate json report 2"
        
	# generate txt report
	# the format of the txt template was based on cuckoo's version 0.3 txt report and was modified to present profiler's results
	"""
	    # Cuckoo Sandbox - Automated Malware Analysis
        # Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
        # http://www.cuckoobox.org """                
          
        txt_report = ""
        txt_report += "================================================================================\n"

        txt_report += "                                       _                  \n"
        txt_report += "                      ____ _   _  ____| |  _ ___   ___    \n"
        txt_report += "                     / ___) | | |/ ___) |_/ ) _ \\ / _ \\ \n"
        txt_report += "                    ( (___| |_| ( (___|  _ ( |_| | |_| |  \n"
        txt_report += "                     \\____)____/ \\____)_| \_)___/ \\___/ Profiler\n"
        txt_report += "\n"
        txt_report += "                              Profile Report\n"
        txt_report += "                            <----------------->\n"
        txt_report += "                             www.cuckoobox.org\n"
        txt_report += "\n"
        txt_report += "================================================================================\n"
        txt_report += " Analysis of %s\n" % profile["malware_info"]["name"]
        txt_report += " MD5 %s\n" % profile["malware_info"]["md5"]
        txt_report += " Total Executions:    %s\n" % profile["total_executions"]
        txt_report += "================================================================================\n"
        txt_report += "\n"

	# Menu
        txt_report += "================================================================================\n"
        txt_report += " Content Menu\n"
        txt_report += "================================================================================\n"
        txt_report += "\n"
        txt_report += "    1. General information\n"
        txt_report += "    2. Dropped files\n"

	# Count dropped files     
        dropped_all_execs = []
        dropped_unique = []
        dropped_varied = []
        if profile["results"]["dropped"] and len(profile["results"]["dropped"]) > 0:
            counter_total = 0
            counter_all = 0
            counter_unique = 0
            counter_varied = 0
            counter_repeated = 0
            for dropped in profile["results"]["dropped"]:
                if len(dropped["analysis"]) == total:
                    dropped_all_execs.append(dropped)
                    counter_all += 1
                elif len(dropped["analysis"]) == 1 and total != 1:
                    dropped_unique.append(dropped)
                    counter_unique += 1
                else:
                    dropped_varied.append(dropped)
                    counter_varied += 1           
                if dropped["repeated"] > 0:
                    counter_repeated += 1
         
	# Create dropped files stacked bar chart

            N = 3
            df_all = (0, counter_all, 0)
            df_varied = (0, counter_varied, 0)
            df_unique = (0, counter_unique, 0)       
            ind = np.arange(N)    # the x locations for the groups
            width = 0.40       # the width of the bars

            p1 = plt.bar(ind, df_all,   width, color='r')
            p2 = plt.bar(ind, df_varied, width, color='g',
                         bottom=df_all)
            p3 = plt.bar(ind, df_unique, width, color='b',
                          bottom=(counter_all+counter_varied))
            
            plt.ylabel('Dropped Files')
            plt.title('Dropped Files By Number of Appearences')
            plt.xticks(ind+width/2., (' ', 'Total ', ' '))
            plt.yticks(np.arange(0,(counter_all+counter_varied+counter_unique)+1,2))
            plt.legend( (p1[0], p2[0], p3[0]), ('All Execs '+str(counter_all), 'Varied '+str(counter_varied), 'Unique '+str(counter_unique)) )
            
            fig_file_name = "dropped_stacked.png"
            fig_path = os.path.join(charts_path, fig_file_name)

            plt.savefig(fig_path, dpi=128)
            plt.figure()
           

	# Continue with txt report 
            txt_report += ("        %d Total different dropped files\n" 
                                    % (len(profile["results"]["dropped"])))
            txt_report += ("        %d Files were dropped in all executions\n" 
                                     % (counter_all))
            txt_report += ("        %d Files were dropped only in one execution\n" 
                                     % (counter_unique))
            txt_report += ("        %d Files were dropped in various executions\n" 
                                     % (counter_varied))
            if counter_repeated > 0:
                txt_report += ("        %d Files were repeated inside the same execution\n" 
                                     % (counter_repeated))

            txt_report += ("     Files dropped in all executions\n") 
            counter = 1                    
            for dropped in dropped_all_execs:
                txt_report += ("        2.%d File: %s\n" 
                                 % (counter, dropped["name"]))
                counter += 1
                
            txt_report += ("     Files dropped in one execution\n")                           
            for dropped in dropped_unique:
                txt_report += ("        2.%d File: %s\n" 
                                 % (counter, dropped["name"]))
                counter += 1
            txt_report += ("     Files dropped in various executions\n") 
            for dropped in dropped_varied:
                txt_report += ("        2.%d File: %s\n" 
                                 % (counter, dropped["name"]))
                counter += 1
        txt_report += "    3. Network analysis\n"
        txt_report += "        3.1 DNS requests\n"
        txt_report += "        3.2 HTTP requests\n"
        txt_report += "    4. Behavior analysis\n"

        counter = 1
        for process in profile["results"]["behavior"]["processes"]:
            txt_report += ("        4.%d Process: %s (%s)" 
                             % (counter, process["process_name"],
                                process["process_id"]))
            counter += 1

            if len(process["analysis"]) == total:
                txt_report += ("      Found in all executions\n")
            else:
                txt_report += ("      Found in some executions\n") 

            txt_report += ("                 %d Total different API Calls\n" 
                                    % (len(process["calls"])))
            
            apicalls_all = 0
            apicalls_unique = 0
            apicalls_varied = 0
                                         
            for call in process["calls"]:
                if len(call["analysis"]) == total:          
                    apicalls_all += 1
                elif len(call["analysis"])== 1 and total != 1:
                    apicalls_unique += 1                    
                else:
                    apicalls_varied += 1 
            txt_report += ("                 %d APIs found in all executions\n" 
                                     % (apicalls_all))
            txt_report += ("                 %d APIs found in only in one execution\n" 
                                     % (apicalls_unique))
            txt_report += ("                 %d APIs found in various executions\n" 
                                     % (apicalls_varied))    
             
        txt_report += "\n"

	# General Information
        txt_report += "================================================================================\n"
        txt_report += " 1. General information\n"
        txt_report += "================================================================================\n"
        txt_report += "\n"

        txt_report += "\n"
        txt_report += "File name: %s\n" % profile["malware_info"]["name"]
        txt_report += "File size: %d bytes\n" % profile["malware_info"]["size"]
        txt_report += "File type: %s\n" % profile["malware_info"]["type"]
        txt_report += "CRC32:     %s\n" % profile["malware_info"]["crc32"]
        txt_report += "MD5:       %s\n" % profile["malware_info"]["md5"]
        txt_report += "SHA-1:     %s\n" % profile["malware_info"]["sha1"]
        txt_report += "SHA-256:   %s\n" % profile["malware_info"]["sha256"]
        txt_report += "SHA-512:   %s\n" % profile["malware_info"]["sha512"]
        txt_report += "Ssdeep:    %s\n" % profile["malware_info"]["ssdeep"]

        txt_report += "\n"

        txt_report += "Total Executions:    %s\n" % profile["total_executions"]
        txt_report += "Executions ID:    %s\n" 
        counter = 1
        for execs in profile["executions_summary"]:
                txt_report += "[1.%d] \"%s\":\n" % (counter, execs["exec_id"])
                
                if "analysis_path" in execs["analysis_info"]:
                    txt_report += "            Analysis Path: %s\n" % (execs["analysis_info"]["analysis_path"])
                    
                txt_report += "            Started      : %s\n" % (execs["analysis_info"]["started"])
                txt_report += "            Ended        : %s\n" % (execs["analysis_info"]["ended"])
                txt_report += "            Duration     : %s\n" % (execs["analysis_info"]["duration"])
                txt_report += "            Dropped Files: %s\n" % (execs["total_dropped_files"])
                txt_report += "            Processes    : %s\n" % (execs["total_processes"])
                txt_report += "            Api Calls    : \n"
                for proc in execs["api_calls"]:
                    txt_report +=( "                          %s :  %d \n" % 
                                                (proc, execs["api_calls"][proc]))
                txt_report += "\n"

                counter += 1
	# Dropped files
        txt_report += "================================================================================\n"
        txt_report += " 2. Dropped files\n"
        txt_report += "================================================================================\n"
        txt_report += "\n"

        txt_report += (" ***    Files dropped in all executions   ***\n") 
        txt_report += "\n"
        counter = 1
        if len(dropped_all_execs) > 0:
    #        counter = 1
            for dropped in dropped_all_execs:
                txt_report += "[2.%d] \"%s\":\n" % (counter, dropped["name"])
                txt_report += "  File size: %s bytes\n" % dropped["size"]
                txt_report += "  File type: %s\n" % dropped["type"]
                txt_report += "  CRC32:     %s\n" % dropped["crc32"]
                txt_report += "  MD5:       %s\n" % dropped["md5"]
                txt_report += "  SHA-1:     %s\n" % dropped["sha1"]
                txt_report += "  SHA-256:   %s\n" % dropped["sha256"]
                txt_report += "  SHA-512:   %s\n" % dropped["sha512"]
                txt_report += "  Ssdeep:    %s\n" % dropped["ssdeep"]
                if len(dropped["same_as"]) > 0:
                     counter_same = 1
                     txt_report += ("  Same as :\n") 
                     for same in dropped["same_as"]:
                         txt_report +=( "             %d  \"%s\" in analysis : \"%s\" \n" % 
                                    (counter_same, same["name"], same["in_analysis"] ))
                         counter_same += 1
                if dropped["repeated"] > 0:
                        txt_report += ("  Repeated : %d times \n" % (dropped["repeated"])) 
                txt_report += "\n"

                counter += 1
        else:
            txt_report += "Nothing to display.\n"

        txt_report += "\n"

        txt_report += (" ***    Files dropped in only one execution   ***\n") 
        txt_report += "\n"
        if len(dropped_unique) > 0:
            for dropped in dropped_unique:
                txt_report += "[2.%d] \"%s\":\n" % (counter, dropped["name"])
                txt_report += "  File size: %s bytes\n" % dropped["size"]
                txt_report += "  File type: %s\n" % dropped["type"]
                txt_report += "  CRC32:     %s\n" % dropped["crc32"]
                txt_report += "  MD5:       %s\n" % dropped["md5"]
                txt_report += "  SHA-1:     %s\n" % dropped["sha1"]
                txt_report += "  SHA-256:   %s\n" % dropped["sha256"]
                txt_report += "  SHA-512:   %s\n" % dropped["sha512"]
                txt_report += "  Ssdeep:    %s\n" % dropped["ssdeep"]
                txt_report += "  Dropped in Analysis :  \"%s\" \n" % dropped["analysis"][0]
                
                if dropped["repeated"] > 0:
                        txt_report += ("  Repeated : %d times \n" % (dropped["repeated"])) 
                txt_report += "\n"

                counter += 1
        else:
            txt_report += "Nothing to display.\n"


        txt_report += (" ***    Files dropped in various executions   ***\n") 
        txt_report += "\n"
        if len(dropped_varied) > 0:
            for dropped in dropped_varied:
                txt_report += "[2.%d] \"%s\":\n" % (counter, dropped["name"])
                txt_report += "  File size: %s bytes\n" % dropped["size"]
                txt_report += "  File type: %s\n" % dropped["type"]
                txt_report += "  CRC32:     %s\n" % dropped["crc32"]
                txt_report += "  MD5:       %s\n" % dropped["md5"]
                txt_report += "  SHA-1:     %s\n" % dropped["sha1"]
                txt_report += "  SHA-256:   %s\n" % dropped["sha256"]
                txt_report += "  SHA-512:   %s\n" % dropped["sha512"]
                txt_report += "  Ssdeep:    %s\n" % dropped["ssdeep"]
                txt_report += ("  Dropped in %d out of %d executions\n" % 
                                  (len(dropped["analysis"]), profile["total_executions"] ))

                counter_analysis = 1
                txt_report += ("  Dropped in analysis :\n") 
                for analysis in dropped["analysis"]:
                    txt_report +=( "                %d. \"%s\" \n" % (counter_analysis, analysis))
                    counter_analysis += 1

                if len(dropped["same_as"]) > 0:
                     counter_same = 1
                     txt_report += ("  Same as :\n") 
                     for same in dropped["same_as"]:
                         txt_report +=( "             %d.  \"%s\" in analysis : \"%s\" \n" % 
                                    (counter_same, same["name"], same["in_analysis"] ))
                         counter_same += 1

                if dropped["repeated"] > 0:
                        txt_report += ("  Repeated : %d times \n" % (dropped["repeated"])) 
                txt_report += "\n"

                counter += 1
        else:
            txt_report += "Nothing to display.\n"

        txt_report += "\n"
        txt_report += "\n"

	# Network
        txt_report += "================================================================================\n"
        txt_report += " 3. Network analysis\n"
        txt_report += "================================================================================\n"
        txt_report += "\n"

        txt_report += "[3.1] DNS Requests:\n"
        if profile["results"]["network"] and \
            len(profile["results"]["network"]["dns"]) > 0:
            for dns in profile["results"]["network"]["dns"]:
                txt_report += ("  Hostname: %s, IP: %s\n"
                                 % (dns["hostname"], dns["ip"]))
                                 
                counter_dns = 1
                txt_report += ("  In analysis :\n") 
                for analysis in dns["analysis"]:
                    txt_report +=( "                %d. \"%s\" \n" % (counter_dns, analysis))
                    counter_dns += 1                 
                                 
        else:
            txt_report += "  Nothing to display.\n"

        txt_report += "\n"

        txt_report += "[3.2] HTTP Requests:\n"
        if profile["results"]["network"]["http"]:
            if profile["results"]["network"] and \
               len(profile["results"]["network"]["http"]) > 0:
                for http in profile["results"]["network"]["http"]:
                    txt_report += ("  Host: %s, Port: %s, URI: %s\n"
                                     % (http["host"], http["port"], http["uri"]))
                                 
                    counter_http = 1
                    txt_report += ("  In analysis :\n") 
                    for analysis in http["analysis"]:
                        txt_report +=( "                %d. \"%s\" \n" % (counter_http, analysis))
                        counter_http += 1 
        else:
            txt_report += "  Nothing to display.\n"

        txt_report += "\n"

	# Processes
        txt_report += "================================================================================\n"
        txt_report += " 4. Behavior analysis\n"
        txt_report += "================================================================================\n"
        txt_report += "\n"

        behavior_grouped = []
        
        if profile["results"]["behavior"]["processes"] and \
           len(profile["results"]["behavior"]["processes"]) > 0:
            counter = 1
            for process in profile["results"]["behavior"]["processes"]:
                txt_report += ("[4.%d] Process: %s (%s):\n"
                                 % (counter,
                                    process["process_name"],
                                    process["process_id"]))
                                    
                processes_grouped = {}
                processes_grouped["analysis"] = []
                processes_grouped["process_name"] = process["process_name"]
                processes_grouped["analysis"] = process["analysis"]
                processes_grouped["calls_all"] = []
                processes_grouped["calls_unique"] = []
                processes_grouped["calls_varied"] = []

                calls_all_execs = []
                calls_unique = []
                calls_varied = []
                apicalls_all = 0
                apicalls_unique = 0
                apicalls_varied = 0
                
                txt_report += " ***  Unique Api Calls  ***:\n"
                               
                for call in process["calls"]:
                    if len(call["analysis"]) == total:
                        calls_all_execs.append(call)
                        apicalls_all += 1
                    elif len(call["analysis"])== 1 and total != 1:
                        calls_unique.append(call)
                        apicalls_unique += 1
                        txt_report += ("  (%s) Function: %s, Status: %s, Return: %s\n"
                                     % (call["timestamp"],
                                        call["api"],
                                        call["status"],
                                        call["return"]))
                        txt_report += "  Called in Analysis :  \"%s\" \n" % call["analysis"][0]
                        for argument in call["arguments"]:
                            txt_report += ("      Argument: %s, Value: %s\n"
                                         % (argument["name"],
                                            argument["value"]))

                    else:
                        calls_varied.append(call)
                        apicalls_varied += 1
                
                txt_report += "\n"
            
                txt_report += " ***  Varied Api Calls  ***:\n"

                for call in calls_varied:
                    txt_report += ("  (%s) Function: %s, Status: %s, Return: %s\n"
                                     % (call["timestamp"],
                                        call["api"],
                                        call["status"],
                                        call["return"]))
                      
                    txt_report += ("  Called in %d out of %d executions\n" % 
                                  (len(call["analysis"]), profile["total_executions"] ))

                    counter_analysis = 1
                    txt_report += ("  Called in analysis :\n") 
                    for analysis in call["analysis"]:
                        txt_report +=( "                %d. \"%s\" \n" % (counter_analysis, analysis))
                        counter_analysis += 1

                    for argument in call["arguments"]:
                        txt_report += ("      Argument: %s, Value: %s\n"
                                         % (argument["name"],
                                            argument["value"]))

                txt_report += "\n"
                
                txt_report += " ***  Api Calls called in all executions  ***:\n"

                for call in calls_all_execs:
                    txt_report += ("  (%s) Function: %s, Status: %s, Return: %s\n"
                                     % (call["timestamp"],
                                        call["api"],
                                        call["status"],
                                        call["return"]))
                      
                    for argument in call["arguments"]:
                        txt_report += ("      Argument: %s, Value: %s\n"
                                         % (argument["name"],
                                            argument["value"]))

              
                processes_grouped["calls_all"] = calls_all_execs
                processes_grouped["calls_unique"] = calls_unique
                processes_grouped["calls_varied"] = calls_varied
                behavior_grouped.append(processes_grouped)
                
                txt_report += "\n"
                counter += 1
        else:
            txt_report += "Nothing to display."

        txt_report += "\n"

        txt_file_name = "profile_"+ r +".txt"
        txt_path = os.path.join(profile_path, txt_file_name)

        try:
            report = open(txt_path, "w")
            report.write(txt_report)
            report.close()
        except Exception, why:
            print "Failed writing TXT report: %s" % why

	# create html report
	# the format of the html template was based on cuckoo's version 0.4 html template and was modified to present profiler's results
        try:
            from mako.template import Template
            from mako.lookup import TemplateLookup
            HAVE_MAKO = True
        except ImportError:
            HAVE_MAKO = False

        if not HAVE_MAKO:
                raise ReportError("Failed to generate HTML report: python Mako library is not installed")
                
        #temporary hold chart info for html creation
        if os.path.exists(charts_path):
            profile["results"]["charts"] = []
            charts = []
            counter = 1
            for chart_name in os.listdir(charts_path):
                if not chart_name.endswith(".png"):
                    continue

                chart_path = os.path.join(charts_path, chart_name)

                if os.path.getsize(chart_path) == 0:
                    continue

                chart = {}
                chart["id"] = os.path.splitext(File(chart_path).get_name())[0]
                chart["data"] = base64.b64encode(open(chart_path, "rb").read())
                charts.append(chart)

                counter += 1

            charts.sort(key=lambda chart: chart["id"])
            profile["results"]["charts"] = charts
        else:
            profile["results"]["charts"] = []  
            
        #temprary hold dropped files and API Calls per category for html creation
        # first initialize
        profile["results"]["dropped_all"] = []
        profile["results"]["dropped_unique"] = []
        profile["results"]["dropped_varied"] = []

        profile["results"]["behavior_grouped"] = []
                
        #then pass the values
                
        profile["results"]["dropped_all"] = dropped_all_execs
        profile["results"]["dropped_unique"] = dropped_unique
        profile["results"]["dropped_varied"] = dropped_varied
        profile["results"]["dropped_repeated"] = counter_repeated

        profile["results"]["behavior_grouped"] = behavior_grouped
        
        #temporary put executions info in profile[results]
        profile["results"]["executions_info"] = []
        profile["results"]["executions_info"] = profile["executions_summary"]  
                
        #get the html template               
        lookup = TemplateLookup(directories=[os.path.join("data-profiler", "html")],
                                    output_encoding='utf-8',
                                    encoding_errors='replace')
            
        template = lookup.get_template("report.html")
        htmlresults = {}
        htmlresults = deepcopy(profile["results"])
        html_file_name = "profile_"+ r +".html"
        html_path = os.path.join(profile_path, html_file_name)         

        try:
            html = template.render(**htmlresults)
            print "creating html report"
        except Exception as e:
            print "Failed to generate HTML report: %s" % e.message
            
	  
        try:
            report = open(html_path, "w")
            report.write(html)
            report.close()
        except (TypeError, IOError) as e:
            print "Failed to generate HTML report: %s" % e.message
    else:
        print "No new analyses for malware with md5 :", r    


