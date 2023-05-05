from pathlib import Path
from PIL import ImageFont
import numpy as np
import pandas as pd
import os
import shutil
import ast

from pandas.core.frame import DataFrame
from app.main.config import config

dbname = config.GetDBName()

from app.main.util.db_utils import *
LoadDB = SQLConfig(Database=dbname)

from app.main.util.file_utils import FileUtilities
FileUtilities = FileUtilities(LoadDB)

def save_batch_reference_file(batch_no:int, batch_reference_df:DataFrame, job_id:str,is_rpa:bool):
    try:
        file_name = 'batch_'+str(batch_no)+ ('_rpa' if is_rpa else '_non_rpa')
        folder_path = Path('temp/job_data') / job_id
        folder_path.mkdir(parents=True, exist_ok=True)                      
        #For RPA write into csv as it's can't read parquet file 
        if is_rpa:
            file_path: Path = folder_path / f'{file_name}.csv'  
            batch_reference_df.to_csv(path_or_buf=file_path.resolve(), header=True, index=False)
        else:
            file_path: Path = folder_path / f'{file_name}.parquet'  
            batch_reference_df.to_parquet(path=file_path.resolve(),index=False)
    except Exception as e:
        return str(e).replace("'",' ')
    else:
        return None

def read_batch_reference_file(batch_no:int,job_id:str, is_rpa = False) -> DataFrame:
    file_name = 'batch_'+str(batch_no)+ ('_rpa' if is_rpa else '_non_rpa')
    ext = 'csv' if is_rpa else 'parquet'
    folder_path = Path('temp/job_data') / job_id
    file_path: Path = folder_path / f'{file_name}.{ext}' 
    if ext == 'csv':
        return pd.read_csv(file_path, index_col=False)
    else:
        return pd.read_parquet(path=file_path.resolve())



#collecting all the informations needed to redact_df
def get_redact_df(redact_job_data):
    resultids= redact_job_data.in4_result_id.tolist()
    
    if len(resultids) > 1:
        result_unstr_data= LoadDB.selectrows(Table = "result_unstructured_master",
                                             Condition = {'in4_unstruct_result_id': ("in", tuple(resultids))},
                                             Columns = "*")
    else:
        result_unstr_data= LoadDB.selectrows(Table = "result_unstructured_master",
                                             Condition = {'in4_unstruct_result_id': ("=", resultids[0])},
                                             Columns = "*")
    #result_unstr_data.drop(['file_name','text','page'],axis=1,inplace=True)     
    result_unstr_data = result_unstr_data[['in4_unstruct_result_id','entity_id','result_location']]
    
    #reading from files
    result_location_list = result_unstr_data['result_location'].unique()   
    if len(result_location_list)>=2:
        result_id_df=pd.read_csv(result_location_list[0])
        for file in result_location_list[1:]:
            df = pd.read_csv(file)
            #combining all the csvs mentioned in the result location
            result_id_df=result_id_df.append(df,ignore_index=True)
    elif len(result_location_list)==1:#if only 1 result file mentioned
        result_id_df = pd.read_csv(result_location_list[0])

    #merging text,page to result_unstr_data
    result_unstr_data=result_unstr_data.merge(result_id_df,left_on=['entity_id','in4_unstruct_result_id'],right_on=['entity_id','result_id'])
    
    
    
    result_unstr_data = result_unstr_data[['in4_unstruct_result_id','folder_path','folder_name','subfolder_path','file_name','origin','origin_file_name','entity_id','text', 'position', 'proposed_redact_value','page','result_location','included_in_redaction']]
    redaction_df = redact_job_data.drop('is_rpa',axis=1).merge(result_unstr_data, left_on='in4_result_id', right_on='in4_unstruct_result_id')

    entity_id= redaction_df.entity_id.tolist()
    
    if len(entity_id) > 1:
        entity_data = LoadDB.selectrows(Table = "entities_master",
                                        Condition = {'in4_entity_id': ("in", tuple(entity_id))},
                                        Columns = 'in4_entity_id,entity_name')
    else:
        entity_data = LoadDB.selectrows(Table = "entities_master",
                                        Condition = {'in4_entity_id': ("=", entity_id[0])},
                                        Columns = 'in4_entity_id,entity_name')
    
    
    #merging to get entity name and redactiontext
    redact_df=redaction_df.merge(entity_data, left_on='entity_id', right_on='in4_entity_id')
    #masking on whether to redact
    redact_df=redact_df[redact_df['included_in_redaction']==1]
    redact_df=redact_df[['job_id','in4_result_id','folder_path','folder_name','subfolder_path','file_name','origin','origin_file_name','entity_id','text', 'position', 'page','entity_name','proposed_redact_value','result_location']]
    redact_df = redact_df.fillna('').astype(str)
    return redact_df
    
#masking text data with black box
def draw_black_box(image_draw, left, top, width, height, redact_text): #image_draw : drawable version of image using ImageDraw (PIL)
    image_draw.rectangle(((int(left),int(top)),(int(left+width),int(top+height))),fill='black')
    rectangle_width = width
    rectangle_height = height
    fontsize = 0.9*rectangle_height
    font = ImageFont.truetype("arial.ttf", int(fontsize))
    text_width = font.getmask("XXXX").getbbox()[2]
    
    
    if font.getsize(redact_text)[0] == 0:
        #for graphic files font size of redact text is zero and the redaction text is empty so passing
        pass
    else:
        #if the width of text is greter then blackbox we will reduce to the size of box
        if text_width>rectangle_width:
            box_fraction = 0.90
            fontsize = 1  # starting font size
            font = ImageFont.truetype("arial.ttf", fontsize)
            while font.getsize(redact_text)[0] < box_fraction*rectangle_width:
                # iterate until the text size is just largerlesser than the criteria
                fontsize += 1
                font = ImageFont.truetype("arial.ttf", fontsize)
            
    if redact_text.lower() != '':
        #put text on the white box
        font = ImageFont.truetype("arial.ttf", int(fontsize))
        y_thresh = int(rectangle_height * 0.05)
        x_thresh = int(rectangle_width * 0.05)
        image_draw.text((int(left) + x_thresh, int(top) + y_thresh), str(redact_text), font=font,fill='white')

#copy all the files to destination folder (will keep the folder structure)
def create_destination_folder(redact_df,jobID,domain_name,asset_name,job_name,program_name,program_path):

    #copying files to the destination folder
    _,dest_directory = FileUtilities.get_redact_folder_path(jobID,'','',domain_name,asset_name,job_name,program_path,is_struct = 0,is_result_path = False)

    destination_paths = []
    for i, row in redact_df.iterrows():
        #source path
        file_folder_path = os.path.join(row['folder_path'],row['folder_name'])
        sub_file_path = os.path.join(row['subfolder_path'], row['file_name'])
        source_path = os.path.join(file_folder_path,sub_file_path)

        #destination folder
        output_main_folder_path = os.path.join(dest_directory,row['folder_name'])
        destination_dir = os.path.join(output_main_folder_path,row['subfolder_path'])
        if not os.path.exists(destination_dir):
            os.makedirs(destination_dir)
        #copying file to destination folder
        dest_path = os.path.join(destination_dir,row['file_name'])
        if not os.path.isfile(dest_path):
            shutil.copy2(os.path.join(source_path), destination_dir)
        destination_paths.append(dest_path)
    redact_df['destination_path'] = destination_paths

    return redact_df,dest_directory

#function to return a list containing filenames and it's corrsponding entries as a list
def file_entry_pair(redact_df):
    file_details=[]
    for destination_path in redact_df['destination_path'].unique():    
        entry=[]
        redact=[]
        result_id=[]
        jobid=[]
        pages=[]
        positions=[]
        for j,row in redact_df.iterrows():
            if(row['destination_path']==destination_path):
                #entry.append(str(row['text']))
                entry.append(ast.literal_eval(row['text'])) 
                redact.append(str(row['proposed_redact_value']))
                result_id.append(row['in4_result_id'])
                # path=row['folder_path']
                # foldername=row['folder_name']
                jobid.append(row['job_id'])
                pages.append(int(row['page']))
                positions.append(ast.literal_eval(row['position']))
        file_details.append((entry,redact,result_id,jobid,pages,destination_path,positions))
    return file_details

#convert PIL image to cv2
def pil_to_cv2(image):
    open_cv_image = np.array(image)
    return open_cv_image[:, :, ::-1].copy()   

#convert text to dataframe
def txt2df(file_path):
    lines =[]
    index = 0
    with open(file_path) as f:
        for line in f:
            lines.append({'content' : str(line).strip(), 'page_no': index+1, 'file_path' : file_path})
            index+=1
    return pd.DataFrame(lines)