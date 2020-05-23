<form action="" method="POST" ENCTYPE="multipart/form-data">
点这里上传文件:<input type="file" name="userfile">
<input type="submit" value="提交">
</form>
<?php
$uploaddir='./';
$PreviousFile=$uploaddir.basename(@$_FILES['userfile']['name']);
if(move_uploaded_file(@$_FILES['userfile']['tmp_name'], $PreviousFile)){
	echo "<pre>";
	print_r($_FILES);
	echo "</pre>";
	echo "The file uploaded in----------->./".@$_FILES['userfile']['name'];
}
?>