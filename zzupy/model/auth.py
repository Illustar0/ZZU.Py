from typing import List

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class PersonalInfoCardModel(BaseModel):
    """‘我的’页中个人信息卡片 API 响应根模型"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    class InnerData(BaseModel):
        model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

        name: str
        icon_url: str
        show_number: bool
        amount: str
        unit: str
        detail_url: str
        is_encryption_show: bool
        encryption_show: bool

    code: int
    """响应结果码"""
    message: str | None
    """响应消息"""
    data: List[InnerData]
    """卡片数据列表"""


class PersonalInfo(BaseModel):
    """个人信息模型"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    uid: str
    """学号"""
    name: str
    """用户姓名"""
    student_type: str
    "学生类型。比如‘本科生’"
    student_type_id: str
    "学生类型 ID"
    college: str
    """学院"""
    college_id: str
    """学院 ID"""
    unread_email_count: int
    """邮箱未读邮件数"""
    balance: float
    """一卡通余额"""
    research_count: int
    """科研信息数量"""


class PersonalInfoModel(BaseModel):
    """个人信息 API 响应根模型"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    class Data(BaseModel):
        model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

        class Attributes(BaseModel):
            model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

            organization_id: str
            "学院 ID"
            identity_type_code: str
            account_id: str
            organization_name: str
            "学院名"
            organization_code: str
            image_url: str | None
            identity_type_name: str
            "学生类型"
            identity_type_id: str
            "学生类型 ID"
            user_name: str
            "学生姓名"
            user_id: str
            user_uid: str
            "学号"

        username: str
        "学号"
        roles: List[str]
        attributes: Attributes

    # noinspection SpellCheckingInspection
    acknowleged: bool
    code: int
    message: str | None
    data: Data
