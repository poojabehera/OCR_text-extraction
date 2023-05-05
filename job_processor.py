from multiprocessing import get_context
import os
import shutil
from pathlib import Path
from typing import Dict, List, Text, Tuple
from flask_sqlalchemy import model
import numpy as np
from pandas.core.frame import DataFrame
from app.main.service.database.job_service import look_up_job
from app.main.model.result_unstructured_master import ResultUnstructuredMaster
from app.main.service.redact.unstructured.redact_process import redact_chunck
from app.main.service.scan.unstructured.scan_process import check_job_status
from jobFunctions import get_CPU_count
from ..redact_job_processor import RedactJobProcessor
from app.main.model.job_dto import JobInfo, JobMessage, RedactJobInfo,ScanResult,ScanResultEntity
from app.main.model.scan_result_dto import RedactReferenceRecord
from app.main.model.file_dto import Status
from app.main.model.redact_audit import RedactAudit
from app.main.model.redact_entity_audit import RedactEntityAudit
from app.main.util.file_utils import combine_file_path, is_rpa_file
from app.main.util.constants import JobStatus
from app.main.util.logging_util import logger
from app.main.service.redact.unstructured.redact_utils import save_batch_reference_file,read_batch_reference_file
from app.main.service.database.result_unstructured_master_service import read_result_info_for_job
from app.main.service.database.redact_audit_service import lookup_redact_audits, lookup_unfinished_batches, save_redact_audits
import traceback
from multiprocessing import get_context, TimeoutError, Pool
import pandas as pd
class UnstructuredJobProcessor(RedactJobProcessor):

    BATCH_SIZE = 500

    SOURCE_PATH = 'source_path'
    DEST_PATH = 'dest_path'
    INCLUDED_IN_REDACTION = 'included_in_redaction'
    FOLDER_PATH = 'folder_path'
    FOLDER_NAME = 'folder_name'
    FILE_NAME ='file_name'
    ENTITY_NAME = 'entity_name'
    RESULT_ID='result_id'
    IS_RPA = 'is_rpa'
    

    def __init__(self, job_info: RedactJobInfo) -> None:
        super().__init__(job_info)

    def __read_filtered_csv(self, result) -> DataFrame:
        #As we are getting huge number of results in the csv
        #We need to only read the records marked as include_in_redaction 
        iter_csv = pd.read_csv(result, iterator=True, chunksize=1000)
        df_result = pd.concat([chunk[chunk[self.INCLUDED_IN_REDACTION] == 1] for chunk in iter_csv])
        columns = df_result.keys()
        if 'folder_name' in columns:
            #TODO: to be removed when report generation updated on scan side
            df_result[self.SOURCE_PATH] = list(map(combine_file_path,df_result[self.FOLDER_PATH],df_result['folder_name'],df_result[self.FILE_NAME]))
        else:
            df_result[self.SOURCE_PATH] = list(map(combine_file_path,df_result[self.FOLDER_PATH],df_result[self.FILE_NAME]))
        df_result[self.IS_RPA] = list(map(is_rpa_file,df_result[self.FILE_NAME]))
        #combine the path
        df_result=df_result.drop(columns=[self.FOLDER_PATH, self.FILE_NAME,'confidence','is_validated'])
        return df_result

    def __get_result_info_for_file(self,scan_results, result_ids)->ScanResult:
        result_info_for_file = ScanResult()
        result_info_for_file.folder_path = scan_results[0].folder_path
        result_info_for_file.folder_name = scan_results[0].folder_name
        result_info_for_file.result_entities = []
        for scan_result in scan_results:
            if scan_result.in4_unstruct_result_id in result_ids:
                result_entity = ScanResultEntity()
                result_entity.result_id = scan_result.in4_unstruct_result_id
                result_entity.entity_id = scan_result.entity_id
                result_entity.entity_name = scan_result.entity_name              
                result_info_for_file.result_entities.append(result_entity)
        return result_info_for_file
    
    def __populate_redact_audit(self,scan_results, entity_results_df:DataFrame, dest_directory: str, is_rpa:bool) -> str:
        batch_no = 1
        redact_audits : List[RedactAudit] = []
        #Stores scan results for all files in this batch.
        #Read the only the csvs for the batch can optimise the memory usage
        batch_reference:List[Dict] = [] 
        unique_file_names = entity_results_df[self.SOURCE_PATH].unique()
        for i, source_path_str in enumerate(unique_file_names):
            df_rows = entity_results_df.loc[entity_results_df[self.SOURCE_PATH] == source_path_str]
            result_ids = df_rows[self.RESULT_ID].unique()
            scan_result : ScanResult = self.__get_result_info_for_file(scan_results,result_ids)
            
            dest_path = source_path_str.replace(scan_result.folder_path, dest_directory)    
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy(source_path_str, dest_path)
            redact_audit = RedactAudit()
            redact_audit.job_id = self.job_info.job_id
            redact_audit.status = Status.loaded.value
            redact_audit.file_path = source_path_str
            redact_audit.is_structured = False
            redact_audit.batch_no = batch_no
            redact_audit.is_rpa = 'Y' if is_rpa else 'N'
            entity_audits = []
            i=0
            for row in df_rows.itertuples(index=False, name='RedactReferenceRecord'):
                row:RedactReferenceRecord
                entity_result = next((r for r in scan_result.result_entities if r.result_id == row.result_id), None)
                entity_audit = RedactEntityAudit()
                entity_audit.entity_id = entity_result.entity_id
                entity_audit.result_id = row.result_id
                entity_audit.redact_status = Status.loaded.value
                entity_audits.append(entity_audit)

                #Temp file part
                readct_reference_record = RedactReferenceRecord(
                    seq_no = i,
                    source_path = row.source_path,
                    dest_path = dest_path,
                    orphan = row.orphan,
                    origin_file_path = row.origin_file_path,
                    page = row.page,
                    entity_name = row.entity_name,
                    position = row.position,
                    text = row.text,
                    proposed_redact_value = str(row.proposed_redact_value)
                )
                batch_reference.append(readct_reference_record.dict())
                i=i+1

            redact_audit.entity_audits = entity_audits
            redact_audits.append(redact_audit)

            #Save the list and dfs based on batch for memory optimization 
            if len(redact_audits) == self.BATCH_SIZE or len(redact_audits) == (len(unique_file_names) - (batch_no-1) * self.BATCH_SIZE):
                
                '''
                No. of row in the dataframe can be different for each batch 
                as the files can have different number of PII identified 
                '''
                batch_reference_df = pd.DataFrame(batch_reference)
                message = save_batch_reference_file(batch_no=batch_no, batch_reference_df=batch_reference_df, job_id=self.job_info.job_id, is_rpa=is_rpa)
                if message is not None:
                    logger.error(message)
                    return message

                '''
                Saving the dataframe before saving to database. 
                This is to avoid any error during saving csv and have to roll back the records commit to db
                Beceaue the identity field will be oppcupied even save query is rolled back.
                '''
                save_redact_audits(redact_audits=redact_audits)
                batch_no+=batch_no
                redact_audits = []
    
    def check_job_status(self,job_id: str) -> JobStatus:
        """
        check job status for error handling
        """
        try:
            job_record = look_up_job(job_id, refresh=True)
        except:
            logger.error(f'Failed to check job status for {job_id}')
            logger.error(traceback.format_exc())
            return None
        else:
            return JobStatus(job_record.job_status)
            
    #This might be able to move to the parent class depending on how the structured redaction is working            
    def redact_batch(self, redact_audits:List[RedactAudit]) -> JobMessage:
        batch_no = redact_audits[0].batch_no
        redact_reference_df = read_batch_reference_file(batch_no, self.job_info.job_id)

        job_status = JobStatus.InProgress

        args=[]
        results = []
        cpu_count = get_CPU_count()
        job_messages = JobMessage(job_status = JobStatus.InProgress)
        if len(redact_audits) >= cpu_count:
            split_file_details:List[RedactAudit] = list(np.array_split(redact_audits, cpu_count))
        else:
            split_file_details: List[RedactAudit] = list(np.array_split(redact_audits, len(redact_audits)))
        for files in split_file_details:
            #lets only pass a sub set of df for each process
            sub_df = pd.concat([redact_reference_df[redact_reference_df[self.SOURCE_PATH] == file.file_path] for file in files])
            args.append((files, sub_df))

        logger.info('Multiprocessing Started')
        with get_context("spawn").Pool(cpu_count) as pool:             
            outputs=pool.starmap_async(redact_chunck,args)
            while True:
                try:
                    results = outputs.get(30)
                    break
                except TimeoutError:
                    job_status = self.check_job_status(self.job_info.job_id)
                    if job_status.value == JobStatus.Cancelling.value:
                        job_messages = JobMessage(job_status = JobStatus.Cancelling)
                        logger.debug('Cancelling Detected. Terminating multiprocess pool')
                        pool.terminate()
                        break
                except Exception as e:
                    logger.exception(e)
                    job_messages.messages.append(str(e).replace("'", ' '))
                    break
            pool.close
            pool.terminate()
        redact_audits:list[RedactAudit] = []
        flat_result_pairs: List[RedactAudit] = [pair for sublist in results for pair in sublist]
        for redact_audit in flat_result_pairs:
            redact_audits.append(redact_audit)
        save_redact_audits(redact_audits, True)
        
        if job_status == JobStatus.Cancelling:
            logger.info('Job cancelled. Terminated process pool')
        else:
            logger.info('Multiprocessing Completed')
        return job_messages


    def load_redact_data(self) -> str:
        #Check if data already loaded.
        if len(lookup_unfinished_batches(self.job_info.job_id, False)) > 0:
            return None
        #1. read all the scan results based on job info
        scan_results_info = read_result_info_for_job(self.job_info.result_ids)
        
        #2. read all entity reports
        result_location_list:List[str] = []
        for result_info in scan_results_info:
            if result_info.result_location not in result_location_list:
                result_location_list.append(result_info.result_location)
        
        for i, result in enumerate(result_location_list):
            if i == 0:
                entity_results_df:DataFrame = self.__read_filtered_csv(result)
            else:
                entity_results_df = entity_results_df.append(self.__read_filtered_csv(result), ignore_index = True)
        entity_results_df.sort_values(by=[self.SOURCE_PATH]) 
        dest_directory = self._get_dest_path()
                
        #3 Populate redact_audit table and break down entity scan results for batch
        message = self.__populate_redact_audit(scan_results_info,entity_results_df[entity_results_df[self.IS_RPA] == False], dest_directory,is_rpa=False)
        if message is not None:            
            return message
        message = self.__populate_redact_audit(scan_results_info,entity_results_df[entity_results_df[self.IS_RPA] == True], dest_directory, is_rpa=True)
        if message is not None:
            return message
        return None

    def process(self) -> JobStatus:
        return super().process()