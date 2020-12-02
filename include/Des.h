#ifndef __DES_H__
#define __DES_H__

#ifdef __cplusplus
extern "C" {
#endif

/** \brief ��� ���������� (padding) ��� ���������� MAC */
#define DES_PADDING_ZERO                  0x00         /**< ��������� ������ */
#define DES_PADDING_EMV                   0x01         /**< ��������� � ������������  */
#define DES_PADDING_NONE                  0x02         /**< �� ���������, Padding ������ �� ������ �������.   */

/**
  @brief ������� 8 ������ ������ �� ��������� DES.
  @param p_pKey       - ��������� �� �����, ���������� 8-�������� ��������
                        ����� ��� ������ �������� ����� ��������� ����������.
  @param p_pInBuffer  - ��������� �� �����, ���������� 8 ������ ������, �������
                        ����� �����������.
  @param p_pOutBuffer - ��������� �� �����, ���� ����� �������� 8 ������
                        ������������� ������
*/
URC Des_Single_Encrypt (PCUINT8 p_pKey, PCUINT8 p_pInBuffer, PUINT8 p_pOutBuffer);

/**
  @brief �������������� 8 ������ ������ �� ��������� DES.
  @param p_Key        - ��������� �� �����, ���������� 8-�������� ��������
                        ����� ��� ������ �������� ����� ��������� �����������.
  @param p_pInBuffer  - ��������� �� �����, ���������� 8 ���� �������������
                        ������
  @param p_pOutBuffer - ��������� �� �����, ���� ����� �������� 8 ����
                        �������������� ������
*/
URC Des_Single_Decrypt (PCUINT8 p_pKey, PCUINT8 p_pInBuffer, PUINT8 p_pOutBuffer);

/**
  @brief ������� 8 ������ ������ �� ��������� 3DES.

  @param p_Key        - ��������� �� �����, ���������� 16-�������� ��������
                        ����� ��� ������ �������� ����� ��������� ����������.
  @param p_pInBuffer  - ��������� �� �����, ���������� 8 ������ ������, �������
                        ����� �����������.
  @param p_pOutBuffer - ��������� �� �����, ���� ����� �������� 8 ������
                        ������������� ������.
*/
URC Des_Triple_Encrypt (PCUINT8 p_Key, PCUINT8 p_pInBuffer, PUINT8 p_pOutBuffer);

/**
  @brief �������������� 8 ������ ������ �� ��������� 3DES.
  @param p_Key        - ��������� �� �����, ���������� 16-�������� ��������
                        ����� ��� ������ �������� ����� ��������� �����������.
  @param p_pInBuffer  - ��������� �� �����, ���������� 8 ���� �������������
                        ������
  @param p_pOutBuffer - ��������� �� �����, ���� ����� �������� 8 ����
                        �������������� ������
*/
URC Des_Triple_Decrypt (PCUINT8 p_Key, PCUINT8 p_pInBuffer, PUINT8 p_pOutBuffer);

/**
    @brief ������� 8 ������ ������ �� ��������� 3DES-CBC.
    @param p_Key        - ��������� �� �����, ���������� 16-�������� ��������
    ����� ��� ������ �������� ����� ��������� ����������.
    @param p_pInBuffer  - ��������� �� �����, ���������� 8 ������ ������, �������
    ����� �����������.
    @param p_pOutBuffer - ��������� �� �����, ���� ����� �������� 8 ������
    ������������� ������.
*/
URC Des_Cbc_Encrypt (PCUINT8 p_Key,
                     PCUINT8 p_pInBuffer, 
                     UINT16  p_Len,
                     PUINT8  p_pIV,
                     UINT8   p_Padding,
                     PUINT8  p_pOutBuffer);

/**
    @brief �������������� 8 ������ ������ �� ��������� 3DES-CBC.
    @param p_Key        - ��������� �� �����, ���������� 16-�������� ��������
        ����� ��� ������ �������� ����� ��������� �����������.
    @param p_pInBuffer  - ��������� �� �����, ���������� 8 ���� �������������
        ������
    @param p_pOutBuffer - ��������� �� �����, ���� ����� �������� 8 ����
        �������������� ������
*/
URC Des_Cbc_Decrypt (PCUINT8 p_Key,
                     PCUINT8 p_pInBuffer, 
                     UINT16  p_Len,
                     PUINT8  p_pIV,
                     UINT8   p_Padding,
                     PUINT8  p_pOutBuffer);


#ifdef __cplusplus
}
#endif

#endif /* __DES_H__ */
