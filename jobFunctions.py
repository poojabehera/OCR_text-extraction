import pandas as pd
import numpy as np
import json
import os
from app.main.config import config
from app.main.model.job_dto import DataType

dbname = config.GetDBName()
processor_percentage = config.GetProcessorPercentage()
rpa_supported_file_type = config.GetRpaFileType()

#Connecting to DB
from app.main.util.db_utils import *
LoadDB = SqlConfig

#get path of all files inside a folder
def get_file_paths(folder_path):
    file_paths = []
    for root, dirs, files in os.walk(os.path.abspath(folder_path)):
        for file in files:
            file_paths.append(os.path.join(root, file))

    return file_paths

#get Domain and data asset name from db
def get_job_domain(domain_id):
    domain_data = LoadDB.selectrows(Table = "port_domain",
                                        Condition = {'domain_id': ("=", f"'{domain_id}'")},
                                        Columns = "domain_name,landing_folder_path,assured_folder_path")
    domain_name = domain_data['domain_name'].to_list()[0]
    domain_landing_path = domain_data['landing_folder_path'].to_list()[0]
    domain_assured_path = domain_data['assured_folder_path'].to_list()[0]
    return domain_name, domain_landing_path, domain_assured_path

def get_job_asset(data_asset_id):
    asset_name = LoadDB.selectrows(Table = "data_asset",
                                        Condition = {'data_asset_id': ("=", f"'{data_asset_id}'")},
                                        Columns = "data_set_name")
    asset_name = asset_name['data_set_name'].to_list()[0]
    return asset_name

def get_program(program_id):
    program_data = LoadDB.selectrows(Table = "program",
                                        Condition = {'program_id': ("=", f"'{program_id}'")},
                                        Columns = "program_name,landing_folder_path,assured_folder_path")
    program_name = program_data['program_name'].to_list()[0]
    #program_path = program_data['folder_path'].to_list()[0]
    program_landing_path = program_data['landing_folder_path'].to_list()[0]
    program_assured_path = program_data['assured_folder_path'].to_list()[0]
    return program_name, program_landing_path, program_assured_path


#to get the scan job data
def get_scan_jobdata(job_id,data_type):

    if data_type:
        data_type = DataType.structured
        job_data = LoadDB.selectrows(Table = "structured_job_master",
                                        Condition = {'job_id': ("=",f"'{job_id}'" )}, 
                                        Columns = "*")
    else:
        data_type = DataType.unstructured
        job_data = LoadDB.selectrows(Table = "unstructured_job_master",
                                        Condition = {'job_id': ("=",f"'{job_id}'" )}, 
                                        Columns = "*")

    job_data = json.loads(job_data.to_json(orient = 'records'))
    
    program_name, program_landing_path, program_assured_path = get_program(job_data[0]['program_id'])
    domain_name, domain_landing_path, domain_assured_path = get_job_domain(job_data[0]['domain_id'])
    asset_name = get_job_asset(job_data[0]['dataset_id'])

    if domain_assured_path:
        assured_path = domain_assured_path
    else:
        assured_path = program_assured_path
    if domain_landing_path:
        landing_path = domain_landing_path
    else:
        landing_path = program_landing_path

    job_data_final = []
    for job in job_data:

        entity_ids = job['entity_id'].split(',')
        job['program_name'] = program_name
        job['landing_path'] = landing_path
        job['assured_path'] = assured_path
        job['domain_name']= domain_name
        job['asset_name'] = asset_name
        job['entity_id'] =[int(i) for i in entity_ids]
        job_data_final.append(job)
    
    return data_type,job_data_final

#validating scan Job
 #TO DO: either update or remove
def validate_scan_job(job_data_list, data_type, job_id):
   
    try:
        status = ''
        message = ''
        if data_type == DataType.structured:
            check_list = ['db_name','entity_id']
            status_list = []
            for job in job_data_list:
                if all(job[col] not in ['',np.nan] for col in check_list):
                    status_list.append('Success')
                else:
                    status_list.append('Failure')
        else:
            check_list = ['folder_name','folder_path','entity_id']
            status_list = []
            for job in job_data_list:
                if all(job[col] not in ['',np.nan] for col in check_list):
                    status_list.append('Success')
                else:
                    status_list.append('Failure')
                
        if all(elem =='Success' for elem in status_list):
            status = 'Success'
            message = 'Job initiated'
        else:
            status = 'Failure'
            message = 'Some entries are missing in the job table'
        val_output = {'status' : status,'message' : message }

    except Exception as e:
        err=str(e).replace("'",' ')
        val_output ={'status' : "Failure",'message' : err }
    return val_output

#to get the redact job results
def get_redact_jobdata(job_id):
    redact_job_data = LoadDB.selectrows(Table = "redact_job_master",
                                        Condition = {'job_id': ("=", f"'{job_id}'")},
                                        Columns = "*")
    #redact_job_data['domain_name'] = get_job_domain(redact_job_data['domain_id'].to_list()[0])
    domain_name,domain_landing_path,domain_assured_path = get_job_domain(redact_job_data['domain_id'].to_list()[0])
    redact_job_data['asset_name'] = get_job_asset(redact_job_data['data_asset_id'].to_list()[0])
    #program_name,program_path = get_program(redact_job_data['program_id'].to_list()[0])
    program_name,program_landing_path,program_assured_path = get_program(redact_job_data['program_id'].to_list()[0])
    
    if domain_assured_path:
        assured_path = domain_assured_path
    else:
        assured_path = program_assured_path
    if domain_landing_path:
        landing_path = domain_landing_path
    else:
        landing_path = program_landing_path

    redact_job_data['domain_name'] = domain_name
    redact_job_data['program_name'] = program_name
    redact_job_data['landing_path'] = landing_path
    redact_job_data['assured_path'] = assured_path
    #redact_job_data['program_path'] = program_path
    return redact_job_data

#to get the path of scan results
def get_redact_filedata(redact_input):

    resultids= redact_input.in4_result_id.tolist()
    jobid = redact_input['job_id'].to_list()[0]
    
    if len(resultids) > 1:
        result_unstr_data= LoadDB.selectrows(Table = "result_unstructured_master",
                                             Condition = {'in4_unstruct_result_id': ("in", tuple(resultids))},
                                             Columns = "in4_unstruct_result_id,result_location")
    else:
        result_unstr_data= LoadDB.selectrows(Table = "result_unstructured_master",
                                             Condition = {'in4_unstruct_result_id': ("=", resultids[0])},
                                             Columns = "in4_unstruct_result_id,result_location")

    redact_file_data = result_unstr_data[['in4_unstruct_result_id','result_location']]

    return redact_file_data

#to update is_rpa column in redact_job_master if the job contains docx/msg/xlsx files
def is_RPA_update(redact_input, redact_file_data, extentions = rpa_supported_file_type):
    
    jobid = redact_input['job_id'].to_list()[0]
                                               
    result_unstr_data = redact_input.merge(redact_file_data, left_on='in4_result_id', right_on='in4_unstruct_result_id',how = 'left')
    
    to_redact = []
    for i, row in result_unstr_data.iterrows():

        result_location = row['result_location']
        if os.path.isfile(result_location):
            redact_input = pd.read_csv(result_location,index_col = None)
            redact_input = redact_input[redact_input['included_in_redaction'] == 1]
            if not redact_input.empty:
                is_rpa_col = [1 if name.split('.')[-1].lower() in extentions else 0 for name in redact_input['file_name']]
                if any(elem == 1 for elem in is_rpa_col):
                    LoadDB.updaterows(Table='redact_job_master',
                                    UpdateConditionDict={'is_rpa':1},
                                    ConditionDict={'in4_result_id':('=',f"'{row['in4_unstruct_result_id']}'"),
                                                    'is_structured': ('=',0),
                                                    'job_id': ('=', f"'{jobid}'")})
                to_redact.append(True)
            else:
                to_redact.append(False)
    
    if all(status == False for status in to_redact):
        to_redact_status = False
    else:
        to_redact_status = True

    
    new_redact_input = get_redact_jobdata(jobid)
    
    return new_redact_input, to_redact_status

#check cpu count
def get_CPU_count(): 
    
    cpu_count = os.cpu_count()
    processors = int(cpu_count / (100/processor_percentage))
    n_processor = max(1,processors)
    
    return n_processor



