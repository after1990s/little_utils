create table invTypeMaterials(
	ID BIGINT PRIMARY KEY AUTO_INCREMENT,
	typeID BIGINT,
	materialTypeID BIGINT,
	quantity BIGINT);

create table invTypes(
	ID BIGINT PRIMARY KEY AUTO_INCREMENT,
	typeID BIGINT,
	Name text CHARACTER SET utf8
)character set = utf8;