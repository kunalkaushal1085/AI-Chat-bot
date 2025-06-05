import boto3
from django.conf import settings
from botocore.exceptions import NoCredentialsError
import uuid

def upload_image_to_s3(file_obj, folder="workspace_images"):
    """
    Uploads an image file to AWS S3 and returns the public URL.

    :param file_obj: InMemoryUploadedFile from request.FILES
    :param folder: Folder path in the bucket
    :return: public URL of the uploaded image
    """
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME,
    )

    try:
        file_extension = file_obj.name.split('.')[-1]
        filename = f"{folder}/{uuid.uuid4()}.{file_extension}"

        s3.upload_fileobj(
            file_obj,
            settings.AWS_STORAGE_BUCKET_NAME,
            filename,
            ExtraArgs={'ACL': 'public-read', 'ContentType': file_obj.content_type}
        )

        file_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{filename}"
        return file_url

    except NoCredentialsError:
        raise Exception("AWS credentials not found.")
    except Exception as e:
        raise Exception(f"Failed to upload image: {str(e)}")