from multiprocessing import Pool, get_context
from app.main.service.redact.unstructured.redact_utils import txt2df
import numpy as np
import pandas as pd
import os
from PIL import Image
from .redact_utils import file_entry_pair,create_destination_folder
from .redact_core import pdf_redact, image_redact
from jobFunctions import get_CPU_count
from app.main.config import config

dbname = config.GetDBName()
rpa_supported_file_type = config.GetRpaFileType()

from app.main.util.db_utils import *
LoadDB = SQLConfig(Database=dbname)

from app.main.util.file_utils import FileUtilities
FileUtilities = FileUtilities(LoadDB)
from app.main.util.logging_util import logger
import traceback

#multiprocessing function to loop through files parallely
def redact_batch(file_details,redact_df):
    pid_start= "PID: "+str(os.getpid())+' Started'
    print(pid_start)
    logger.info(pid_start)

    result_unstructured_master_list=[]
    redact_audit_list=[]
    destination_file_list=[details[5] for details in file_details]
    pid_files='Files:'+str(destination_file_list)
    logger.info(pid_files)
    for details in file_details:
        try:
            #ORDER - entry,redact_value,result_id,jobid,pages,destination_path
            entry=details[0]
            redact_value=details[1]
            orginal_result_ids=details[2]
            result_id=list(range(len(entry))) #creating unique id for each entry
            jobid=details[3]
            page_list=details[4]
            redact_file_path = details[5]
            position_list = details[6]
            redact_file_name = os.path.split(redact_file_path)[1]
            file_extension = redact_file_name.split('.')[-1]
            img_list = []
            remarks_list=[]
            status=[]

            if file_extension.lower() in ['png','jpg','jpeg','pdf','tif','tiff','bmp']:
                #pdf redaction
                if file_extension.lower() == 'pdf':
                    img_list, remarks_list  = pdf_redact(redact_file_path,position_list,redact_value,result_id,page_list)
                
                #image redaction    
                else:
                    img, remarks_list = image_redact(redact_file_path,position_list,redact_value,result_id)
                    # image list should only contain single image
                    img_list.append(img)

                #making a flatlist 
                for remark in remarks_list:
                    if(len(remark)>0):#page by page result
                        status.append(remark)

                redact_remark=[]
                #adding msg
                for msg in status:
                    for k in msg:#to remove array of array
                        redact_remark.append(k)

                #list of resultids that got redacted
                success_id=[ids[0] for ids in redact_remark]

                #loop to get the status for result ids
                for ids in result_id:
                    if not ids in success_id:
                        redact_remark.append([ids,"Not Found"])
                    
                #1 for succes 0 for failure(is_redacted column)
                for value in redact_remark:#Eg:[[41, 'Success'],[39, 'Success']]
                    if(value[1]=='Redaction Complete'):
                        value.append(1)
                    else:
                        value.append(0)

                #appending result to result list
                file_audit = []
                for value in redact_remark:
                    ind=result_id.index(value[0])#to get common index value to write back to sql
                    elem={'job_id':jobid[ind],'in4_result_id':orginal_result_ids[ind],'new_value':'Mask',
                        'is_structured':0,'is_redacted':value[2],'remarks':value[1]}
                    result_unstructured_master_list.append({'is_redacted':value[2] , 'in4_unstruct_result_id': orginal_result_ids[ind],'redact_file_path':redact_file_path,'text':entry[ind]})
                    redact_audit_list.append(elem)
                    file_audit.append(elem)
                    
                #imagelist is the list with all image filenames
                img_list2 =[]
                i = 1

                for image in img_list:
                    image = Image.fromarray(image, 'RGB')
                    if i == 1:
                        img1 = image
                    else:
                        img_list2.append(image)
                    i = i + 1

                if len(img_list2) > 0:
                    img1.save(redact_file_path, save_all=True, append_images=img_list2)
                else:
                    img1.save(redact_file_path)

                #updating in detailed audit table
                file_audit_df = pd.DataFrame(file_audit)
                orginal_result_ids = file_audit_df['in4_result_id'].unique()
                for rslt_id in orginal_result_ids:
                    file_result_id = file_audit_df[file_audit_df['in4_result_id']==rslt_id]
                    file_is_redacted = file_result_id['is_redacted'].to_list()
                    audit_data = {'job_id':file_result_id['job_id'].values[0],'in4_result_id':rslt_id,'file_name':redact_file_name}
                    if all(is_red == 1 for is_red in file_is_redacted):
                        audit_data['status'] = 1
                        audit_data['remarks'] = 'Redaction  Complete'
                        LoadDB.insertrows(Table = 'unstructured_detailed_redact_audit', Columns = audit_data)
                    else:
                        failed_remark = list(set(file_result_id[file_result_id['is_redacted'] == 0]['remarks'].to_list()))
                        failed_remark = ", ".join(failed_remark)
                        audit_data['status'] = 0
                        audit_data['remarks'] = failed_remark
                        LoadDB.insertrows(Table = 'unstructured_detailed_redact_audit', Columns = audit_data)
            
            elif file_extension.lower() in ['txt','csv']:
                redact_remark=[]
                redact_file_df = txt2df(redact_file_path) #load file to be redacted into same format when scanning
                for ind in result_id:
                    for position in position_list[ind]:
                        try:
                            line_number = position[0]
                            line_content = redact_file_df.loc[line_number, 'content']
                            redacted_line_content = line_content.replace(str(entry[ind]),str(redact_value[ind]))
                            redact_file_df.loc[line_number, 'content'] = redacted_line_content
                        except Exception as e:
                            redact_remark.append([ind, str(e), 0])
                        else:
                            redact_remark.append([ind, 'Redaction Complete', 1])

                #write results into file
                np.savetxt(redact_file_path, redact_file_df['content'].values, fmt='%s', delimiter="\n")

                #appending result to result list
                file_audit = []
                for value in redact_remark:
                    ind=value[0] #to get common index value to write back to sql
                    elem={'job_id':jobid[ind],'in4_result_id':orginal_result_ids[ind],'new_value':'Mask',
                        'is_structured':0,'is_redacted':value[2],'remarks':value[1]}
                    result_unstructured_master_list.append({'is_redacted':value[2] , 'in4_unstruct_result_id': orginal_result_ids[ind],'redact_file_path':redact_file_path,'text':entry[ind]})
                    redact_audit_list.append(elem)
                    file_audit.append(elem)
                
                #updating in detailed audit table
                file_audit_df = pd.DataFrame(file_audit)
                orginal_result_ids = file_audit_df['in4_result_id'].unique()
                for rslt_id in orginal_result_ids:
                    file_result_id = file_audit_df[file_audit_df['in4_result_id']==rslt_id]
                    file_is_redacted = file_result_id['is_redacted'].to_list()
                    audit_data = {'job_id':file_result_id['job_id'].values[0],'in4_result_id':rslt_id,'file_name':redact_file_name}
                    if all(is_red == 1 for is_red in file_is_redacted):
                        audit_data['status'] = 1
                        audit_data['remarks'] = 'Redaction  Complete'
                        LoadDB.insertrows(Table = 'unstructured_detailed_redact_audit', Columns = audit_data)
                    else:
                        failed_remark = list(set(file_result_id[file_result_id['is_redacted'] == 0]['remarks'].to_list()))
                        failed_remark = ", ".join(failed_remark)
                        audit_data['status'] = 0
                        audit_data['remarks'] = failed_remark
                        LoadDB.insertrows(Table = 'unstructured_detailed_redact_audit', Columns = audit_data)

            else:
                file_audit = []
                for n,row in redact_df.iterrows():
                
                    elem={'job_id':row['job_id'],'in4_result_id':row['in4_result_id'],'new_value':row['proposed_redact_value'],
                            'is_structured':0,'is_redacted':0,'remarks':'Unsupported File Format'}
                    redact_audit_list.append(elem)
                    file_audit.append(elem)
                    result_unstructured_master_list.append({'is_redacted':0, 'in4_unstruct_result_id': row['in4_result_id'],'redact_file_path' : row['destination_path'],'text':row['text']})

                #updating in detailed audit table
                file_audit_df = pd.DataFrame(file_audit)
                orginal_result_ids = file_audit_df['in4_result_id'].unique()
                for rslt_id in orginal_result_ids:
                    file_result_id = file_audit_df[file_audit_df['in4_result_id']==rslt_id]
                    file_is_redacted = file_result_id['is_redacted'].to_list()
                    audit_data = {'job_id':file_result_id['job_id'].values[0],'in4_result_id':rslt_id,'file_name':redact_file_name}
                    failed_remark = 'Unsupported File Format'
                    audit_data['status'] = 0
                    audit_data['remarks'] = failed_remark
                    LoadDB.insertrows(Table = 'unstructured_detailed_redact_audit', Columns = audit_data)
                    

        except Exception as e:
            print(str(e))
            logger.info(details[5])
            logger.info(traceback.format_exc())
            err=str(e).replace("'",' ')
            file_audit = []
            for n,row in redact_df.iterrows():
                
                elem={'job_id':row['job_id'],'in4_result_id':row['in4_result_id'],'new_value':row['proposed_redact_value'],
                        'is_structured':0,'is_redacted':0,'remarks':err}

                redact_audit_list.append(elem)
                file_audit.append(elem)
                result_unstructured_master_list.append({'is_redacted':0, 'in4_unstruct_result_id': row['in4_result_id'],'redact_file_path' : row['destination_path'],'text':row['text']})
            
            #updating in detailed audit table
            file_audit_df = pd.DataFrame(file_audit)
            orginal_result_ids = file_audit_df['in4_result_id'].unique()
            for rslt_id in orginal_result_ids:
                file_result_id = file_audit_df[file_audit_df['in4_result_id']==rslt_id]
                file_is_redacted = file_result_id['is_redacted'].to_list()
                audit_data = {'job_id':file_result_id['job_id'].values[0],'in4_result_id':rslt_id,'file_name':redact_file_name}
                failed_remark = str(e).replace("'",' ')
                audit_data['status'] = 0
                audit_data['remarks'] = failed_remark
                LoadDB.insertrows(Table = 'unstructured_detailed_redact_audit', Columns = audit_data)


    pid_end = "PID: "+str(os.getpid())+" finished its tasks."

    print(pid_end)
    logger.info(pid_end) 
    return redact_audit_list,result_unstructured_master_list


def redact_folder(redact_df, result_df):
    #filtering out jobs for rpa
    redact_df['is_rpa'] =  [1 if name.split('.')[-1].lower() in rpa_supported_file_type else 0 for name in redact_df['file_name']]
    output_df = redact_df.copy()

    jobID = result_df['job_id'][0]
    domain_name = result_df['domain_name'].to_list()[0]
    asset_name = result_df['asset_name'].to_list()[0]
    job_name = result_df['job_name'].to_list()[0]
    program_name = result_df['program_name'].to_list()[0]
    #program_path = result_df['program_path'].to_list()[0]
    landing_path = result_df['landing_path'].to_list()[0]
    assured_path = result_df['assured_path'].to_list()[0]
    #copying file to redact in to destination folder
    redact_df, dest_directory = create_destination_folder(redact_df,jobID,domain_name,asset_name,job_name,program_name,assured_path)
    redact_rpa_df = redact_df[redact_df['is_rpa']==1]
    redact_df=redact_df[redact_df['is_rpa']==0]
    
    
    #execute only if there's value in redact_df after filtering
    if len(redact_df)>0:
    
        #input format name,ent,redact,path,foldername,result_id,jobid in file_details
        file_details = file_entry_pair(redact_df)

        args=[]

        #dividing files based on number of cpus
        cpu_count = get_CPU_count()
        if(len(file_details)>=cpu_count):
            split_file_details = np.array_split(file_details,cpu_count)
        else:
            split_file_details = np.array_split(file_details,len(file_details))

        for files in split_file_details:
            args.append([files,redact_df])
        
        #calling the multiprocessing function
        logger.info('Multiprocessing Started')
        with get_context("spawn").Pool(cpu_count) as pool:
            try:              
                output=pool.starmap(redact_batch,args)
                pool.close
            except Exception as e: # in case of any uncaptured exceptions in the sub-process, terminate the pool
                logger.error('Multiprocessing failed')                            
                logger.exception(e)
                pool.terminate()

        logger.info('Multiprocessing Completed')
        #multiprocessing finished
        fat_result_unstructured_master=[]
        fat_redact_audit=[]
        #retreiving data from multiprocessing function
        for elem in output:
            fat_redact_audit.append(elem[0])
            fat_result_unstructured_master.append(elem[1])
        
        #merging redaction results with redaction df
        is_redacted=[j for i in fat_result_unstructured_master for j in i]
        is_redacted=pd.DataFrame(is_redacted)

        redact_df['text']=redact_df['text'].apply(str)
        #is_redacted['text']=is_redacted['text'].apply(str)
        is_redacted['text']=is_redacted['text'].apply(lambda x: "'" + str(x) + "'") #adding quotes to text column
        if len(is_redacted)>0:
            #Indexing the same text for each file and entity type to avoid duplicates
            is_redacted['text_idx'] = is_redacted.groupby(['in4_unstruct_result_id','redact_file_path','text']).cumcount()+1
            redact_df['text_idx'] = redact_df.groupby(['in4_result_id','destination_path','text']).cumcount()+1
            output_df = pd.merge(redact_df.reset_index(),is_redacted.reset_index(),
                                    left_on=['in4_result_id','destination_path','text','text_idx'],
                                    right_on=['in4_unstruct_result_id','redact_file_path','text','text_idx'],how="left")
        else:
            output_df=redact_df.copy()
            output_df['is_redacted'] = 0

        output_df = pd.concat([output_df, redact_rpa_df]) #adding the rpa rows
        output_df['is_redacted']=[1 if value == 1 else 0 for value in output_df['is_redacted']]

    else:
        output_df['is_redacted'] = 0
    
    #getting all the result_locations
    redact_result_paths = output_df['result_location'].unique()
    logger.info('Saving redacted result files') 
    #writing redaction output to files
    for file_path in redact_result_paths:
        
        redact_output=output_df[output_df['result_location']==file_path]
        folder_name = redact_output['folder_name'].to_list()[0]

        result_file_path,_= FileUtilities.get_redact_folder_path(jobID, file_path, folder_name, domain_name, asset_name, job_name, assured_path, is_struct = 0, is_result_path = True)
        
        #updating redact result file path to db
        result_id = redact_output['in4_result_id'].to_list()[0]
        LoadDB.updaterows(Table='result_unstructured_master',
                            UpdateConditionDict={'redact_result_location':f"'{result_file_path}'",'destination_location' : f"'{dest_directory}'"},
                            ConditionDict={'in4_unstruct_result_id':('=',result_id)})
        
        redact_output=redact_output[redact_output['is_rpa']==0]
        redact_output['serial_no'] = range(1, len(redact_output) + 1)
        redact_output=redact_output[['serial_no','in4_result_id','folder_path','folder_name','subfolder_path','file_name','origin','origin_file_name','page','entity_id','entity_name','position','text','proposed_redact_value','is_redacted']]
        redact_output.rename(columns={'in4_result_id':'result_id', 'proposed_redact_value' : 'redacted_value'}, inplace=True) 
        redact_output=redact_output.drop_duplicates()
        redact_output.to_csv(result_file_path,index=False)