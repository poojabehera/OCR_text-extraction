import os
import traceback
import ast
from typing import List

from PIL import Image
import numpy as np

from app.main.model.redact_audit import RedactAudit
from app.main.model.redact_entity_audit import RedactEntityAudit
from app.main.model.file_dto import Status
from app.main.service.redact.unstructured.redact_core import image_redact, pdf_redact
from app.main.service.redact.unstructured.redact_utils import txt2df
from app.main.util.logging_util import Logger
from pandas.core.frame import DataFrame

logger = Logger()

def set_redact_audit_status(redact_audit: RedactAudit) -> RedactAudit:
    if all(entity_redact.redact_status == Status.redacted.value for entity_redact in redact_audit.entity_audits):
        redact_audit.status = Status.redacted.value
    elif all(entity_redact.redact_status == Status.failed.value for entity_redact in redact_audit.entity_audits):
        redact_audit.status = Status.failed.value
    else:
        redact_audit.status = Status.partialy_redacted
        redact_audit.status = 'Some entity redaction failed for this file'
    return redact_audit
        


def redact_chunck(redact_audits:List[RedactAudit], redact_reference_df: DataFrame) -> List[RedactAudit]:
    pid_start= "PID: "+str(os.getpid())+' Started'
    logger.info(pid_start)

    logger.info('Files {0}'.format(str([redact_audit.file_path for redact_audit in redact_audits])))
    
    for redact_audit in redact_audits:
        redact_audit:RedactAudit
        try:
            redact_records : DataFrame = redact_reference_df[redact_reference_df['source_path'] == redact_audit.file_path]
            dest_file_path:str = redact_records['dest_path'].tolist()[0]
            entries:List[str] = list([ast.literal_eval(text) for text in redact_records['text'].to_list()])
            redact_values:List[str] = redact_records['proposed_redact_value'].to_list()
            sequence_numbers:List[int] = list(range(len(entries)))
            page_list: List[str] = redact_records['page'].to_list()
            position_list = list([ast.literal_eval(position) for position in redact_records['position'].tolist()])
            
            file_extension = redact_audit.file_path.split('.')[-1]

            #replace nan with empty string in redact values
            redact_values: List[str] = ['' if redact_value == 'nan' else redact_value for redact_value in redact_values]

            img_list = []
            remarks_list=[]
            #TODO: abstrat below code into sepreate functions
            if file_extension.lower() in ['png','jpg','jpeg','pdf','tif','tiff','bmp']:
                if file_extension.lower() == 'pdf':
                    img_list, remarks_list  = pdf_redact(dest_file_path,position_list,redact_values,sequence_numbers,page_list)
                    
                #image redaction    
                else:
                    img, remarks_list = image_redact(dest_file_path,position_list,redact_values,sequence_numbers)
                    # image list should only contain single image
                    img_list.append(img)

                for i, entity_audit in enumerate(redact_audit.entity_audits):
                    entity_audit:RedactEntityAudit
                    remark = next((remark[0] == i for remark in remarks_list),None)
                    if remark is not None:
                        entity_audit.redact_status = Status.redacted.value
                    else:
                        entity_audit.redact_status = Status.failed.value
                        entity_audit.remarks = "Not Found"
                
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
                    img1.save(dest_file_path, save_all=True, append_images=img_list2)
                else:
                    img1.save(dest_file_path)

                redact_audit = set_redact_audit_status(redact_audit)
            
            elif file_extension.lower() in ['txt','csv']:
                redact_file_df = txt2df(dest_file_path)
                for ind in sequence_numbers:
                    for position in position_list[ind]:
                        try:
                            line_number = position[0]
                            line_content = redact_file_df.loc[line_number, 'content']
                            redacted_line_content = line_content.replace(str(entries[ind]),str(redact_values[ind]))
                            redact_file_df.loc[line_number,'content'] = redacted_line_content
                        except Exception as e:
                            redact_audit.entity_audits[ind].remarks = str(e)
                            redact_audit.entity_audits[ind].redact_status = Status.failed.value
                        else:
                            redact_audit.entity_audits[ind].redact_status = Status.redacted.value
                
                np.savetxt(dest_file_path, redact_file_df['content'].values, fmt='%s', delimiter="\n")

                redact_audit = set_redact_audit_status(redact_audit)

            else:
                redact_audit.status = Status.failed.value
                redact_audit.remarks = 'Unsupported File Format'
        
        except Exception as e:
            logger.error(traceback.format_exc())
            err=str(e).replace("'",' ')
            redact_audit.status = Status.failed.value
            redact_audit.remarks = err
        finally:
            logger.info(f'{str(redact_audit.file_path)} completed.')
        
    logger.info("{0} finished its tasks.".format(str(os.getpid())))

    return redact_audits




        