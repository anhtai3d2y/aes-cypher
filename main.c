#include "Aes.h"
#include <string.h>
#include <time.h>

typedef struct
{
    uint8_t     state[4][4];
} AesState;

static const uint8_t SBOX[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t RSBOX[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t RCON[11] =
{ 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static void KeyExpansion(uint8_t const*  Key, AesContext* Context)
{
    uint32_t    i;
    uint8_t     k;
    uint8_t     temp [4];

    for( i=0; i < Context->KeySizeInWords; i++ )
    {
        Context->RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        Context->RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        Context->RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        Context->RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    for( i=Context->KeySizeInWords; i<4*(Context->NumberOfRounds+1); i++ )
    {
#ifdef _MSC_VER
#pragma warning( suppress : 6385 )
#endif
        temp[0] = Context->RoundKey[(i-1) * 4 + 0];
        temp[1] = Context->RoundKey[(i-1) * 4 + 1];
        temp[2] = Context->RoundKey[(i-1) * 4 + 2];
        temp[3] = Context->RoundKey[(i-1) * 4 + 3];

// RotWord
        if( 0 == i % Context->KeySizeInWords )
        {
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];

            temp[0] =  temp[0] ^ RCON[i/Context->KeySizeInWords];
        }

        if( AES_KEY_SIZE_256/4 == Context->KeySizeInWords )
        {
            if( 4 == i % Context->KeySizeInWords )
            {
                temp[0] = SBOX[temp[0]];
                temp[1] = SBOX[temp[1]];
                temp[2] = SBOX[temp[2]];
                temp[3] = SBOX[temp[3]];
            }
        }

        Context->RoundKey[i*4 + 0] =
            Context->RoundKey[(i-Context->KeySizeInWords)*4 + 0] ^ temp[0];
        Context->RoundKey[i*4 + 1] =
            Context->RoundKey[(i-Context->KeySizeInWords)*4 + 1] ^ temp[1];
        Context->RoundKey[i*4 + 2] =
            Context->RoundKey[(i-Context->KeySizeInWords)*4 + 2] ^ temp[2];
        Context->RoundKey[i*4 + 3] =
            Context->RoundKey[(i-Context->KeySizeInWords)*4 + 3] ^ temp[3];
    }
}

void KeyInitialization(int* choice, uint8_t const*  Key, AesContext* Context)
{
    int c = choice;
    switch(c)
    {
    case 128:
    {
        AesInitialise128(Key, Context);
        break;
    }

    case 192:
    {
        AesInitialise192(Key, Context);
        break;
    }

    case 256:
    {
        AesInitialise256(Key, Context);
        break;
    }

    default:
        break;
    }
}

static void AddRoundKey(uint32_t Round, AesContext const* Context, AesState* State)
{
    uint32_t  i;
    uint32_t  j;

    for( i=0; i<4; i++ )
    {
        for( j=0; j<4; j++ )
        {
            State->state[i][j] ^= Context->RoundKey[(Round*4*4) + (i*4) + j];
        }
    }
}

static void SubBytes(AesState* State)
{
    uint32_t i;
    uint32_t j;

    for( i=0; i<4; i++ )
    {
        for( j=0; j<4; j++ )
        {
            State->state[j][i] = SBOX[ State->state[j][i] ];
        }
    }
}

static void ShiftRows(AesState* State)
{
    uint8_t temp;

    temp           = State->state[0][1];
    State->state[0][1] = State->state[1][1];
    State->state[1][1] = State->state[2][1];
    State->state[2][1] = State->state[3][1];
    State->state[3][1] = temp;

    temp           = State->state[0][2];
    State->state[0][2] = State->state[2][2];
    State->state[2][2] = temp;

    temp           = State->state[1][2];
    State->state[1][2] = State->state[3][2];
    State->state[3][2] = temp;

    temp           = State->state[0][3];
    State->state[0][3] = State->state[3][3];
    State->state[3][3] = State->state[2][3];
    State->state[2][3] = State->state[1][3];
    State->state[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
    return (x<<1) ^ ( ((x>>7) & 1) * 0x1b );
}

static void MixColumns(AesState* State)
{
    uint32_t  i;
    uint8_t   Tmp;
    uint8_t   Tm;
    uint8_t   t;

    for( i=0; i<4; i++ )
    {
        t   = State->state[i][0];
        Tmp = State->state[i][0] ^ State->state[i][1] ^ State->state[i][2]
              ^ State->state[i][3] ;
        Tm  = State->state[i][0] ^ State->state[i][1] ;
        Tm = xtime(Tm);
        State->state[i][0] ^= Tm ^ Tmp ;
        Tm  = State->state[i][1] ^ State->state[i][2] ;
        Tm = xtime(Tm);
        State->state[i][1] ^= Tm ^ Tmp ;
        Tm  = State->state[i][2] ^ State->state[i][3] ;
        Tm = xtime(Tm);
        State->state[i][2] ^= Tm ^ Tmp ;
        Tm  = State->state[i][3] ^ t ;
        Tm = xtime(Tm);
        State->state[i][3] ^= Tm ^ Tmp ;
    }
}

#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

static void InvMixColumns(AesState* State)
{
    uint32_t    i;
    uint8_t     a;
    uint8_t     b;
    uint8_t     c;
    uint8_t     d;

    for( i=0; i<4; i++ )
    {
        a = State->state[i][0];
        b = State->state[i][1];
        c = State->state[i][2];
        d = State->state[i][3];

        State->state[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b)
                             ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        State->state[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e)
                             ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        State->state[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09)
                             ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        State->state[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d)
                             ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

static void InvSubBytes(AesState* State)
{
    uint32_t  i;
    uint32_t  j;

    for( i=0; i<4; i++ )
    {
        for( j=0; j<4; j++ )
        {
            State->state[j][i] = RSBOX[ State->state[j][i] ];
        }
    }
}

static void InvShiftRows(AesState* State)
{
    uint8_t temp;

    temp = State->state[3][1];
    State->state[3][1] = State->state[2][1];
    State->state[2][1] = State->state[1][1];
    State->state[1][1] = State->state[0][1];
    State->state[0][1] = temp;

    temp = State->state[0][2];
    State->state[0][2] = State->state[2][2];
    State->state[2][2] = temp;

    temp = State->state[1][2];
    State->state[1][2] = State->state[3][2];
    State->state[3][2] = temp;

    temp = State->state[0][3];
    State->state[0][3] = State->state[1][3];
    State->state[1][3] = State->state[2][3];
    State->state[2][3] = State->state[3][3];
    State->state[3][3] = temp;
}

void AesInitialise128(uint8_t const Key [AES_KEY_SIZE_128], AesContext* Context)
{
    memset( Context, 0, sizeof(*Context) );
    //nk
    Context->KeySizeInWords = AES_KEY_SIZE_128 / sizeof(uint32_t);
    //nr
    Context->NumberOfRounds = 10;

    KeyExpansion( Key, Context );
}

void AesInitialise192(uint8_t const Key [AES_KEY_SIZE_192], AesContext* Context)
{
    memset( Context, 0, sizeof(*Context) );
    //nk
    Context->KeySizeInWords = AES_KEY_SIZE_192 / sizeof(uint32_t);
    //nr
    Context->NumberOfRounds = 12;

    KeyExpansion( Key, Context );
}

void AesInitialise256(uint8_t const Key [AES_KEY_SIZE_256], AesContext* Context)
{
    memset( Context, 0, sizeof(*Context) );
    //nk
    Context->KeySizeInWords = AES_KEY_SIZE_256 / sizeof(uint32_t);
    //nr
    Context->NumberOfRounds = 14;

    KeyExpansion( Key, Context );
}

void AesEncrypt(AesContext const* Context, uint8_t const Input [AES_BLOCK_SIZE], uint8_t Output [AES_BLOCK_SIZE])
{
    memcpy( Output, Input, AES_BLOCK_SIZE );
    AesEncryptInPlace( Context, Output );
}

void AesDecrypt(AesContext const* Context, uint8_t const Input [AES_BLOCK_SIZE], uint8_t Output [AES_BLOCK_SIZE])
{
    memcpy( Output, Input, AES_BLOCK_SIZE);
    AesDecryptInPlace(Context, Output );
}

void AesEncryptInPlace(AesContext const* Context, uint8_t Block [AES_BLOCK_SIZE])
{
    uint32_t round = 0;

    AddRoundKey( 0, Context, (AesState*)Block );
    for( round=1; round < Context->NumberOfRounds; round++ )
    {
        SubBytes( (AesState*)Block );
        ShiftRows( (AesState*)Block );
        MixColumns( (AesState*)Block );
        AddRoundKey( round, Context, (AesState*)Block );
//        printf("\nRound %d:", round);
//        ShowBlock(Block);
    }

    SubBytes( (AesState*)Block);
    ShiftRows( (AesState*)Block);
    AddRoundKey( Context->NumberOfRounds, Context, (AesState*)Block );

    printf("Ban ma hoa: ");
    ShowResult(Block);
}

void AesDecryptInPlace(AesContext const* Context, uint8_t Block [AES_BLOCK_SIZE])
{
    uint32_t round = 0;

    AddRoundKey( Context->NumberOfRounds, Context, (AesState*)Block );

    for( round=(Context->NumberOfRounds-1); round>0; round-- )
    {
        InvShiftRows( (AesState*)Block );
        InvSubBytes( (AesState*)Block );
        AddRoundKey( round, Context, (AesState*)Block );
        InvMixColumns( (AesState*)Block );
//        printf("\nRound %d:", Context->NumberOfRounds - round);
//        ShowBlock(Block);
    }
    InvShiftRows( (AesState*)Block );
    InvSubBytes( (AesState*)Block );
    AddRoundKey( 0, Context, (AesState*)Block );

    printf("\nBan giai ma: %s", Block);
//    ShowBlock(Block);
}

//Show result as a string
void ShowResult(uint8_t state[])
{
    for (int i = 0; i < strlen(state); i++)
    {
        printf(" %02hhX ", state[i]);
    }
}

//Show result as a matrix
void ShowBlock(uint8_t state[])
{
    for (int i = 0; i < strlen(state); i++)
    {
        if(i%4 == 0) printf("\n\t");
        printf(" %02hhX ", state[i]);
    }
}
void delay(int number_of_seconds)
{
    // Converting time into milli seconds
    int milli_seconds = 1000 * number_of_seconds;

    // Storing start time
    clock_t start_time = clock();

    // looping till required time is not achieved
    while (clock() < start_time + milli_seconds);
}
int main()
{
    struct AesContext *context = malloc(sizeof(AesContext));
    struct AesState *message = malloc(sizeof(AesState));
    struct AesState *resultEncrypt = malloc(sizeof(AesState));
    struct AesState *resultDecrypt = malloc(sizeof(AesState));
    char Key [32];

    clock_t start, end;
    double calculationTime;

    int choice = 0;
    do
    {
        printf("Nhap do dai khoa \(128, 192 hoac 256\): ");
        scanf("%d", &choice);
        switch(choice)
        {
        case 128:
        case 192:
        case 256:
            break;
        default:
            printf("Do dai khoa khong hop le!\n");
            choice = 0;
            break;
        }
    }
    while(choice == 0);


//  "0123456789ABCDEF"
//  "11111111"
    printf("Nhap key: ");
    fflush(stdin);
    gets(Key);
    while(strlen(Key) != (choice/8)){
        printf("Key chua dung %d ky tu, nhap lai key: ", choice/8);
        fflush(stdin);
        gets(Key);
    }

//    printf("\nKey: %s\n", Key);
//    ShowBlock(Key);
    printf("Nhap ban ro: ");
    fflush(stdin);
    gets(message);
    printf("======================MA HOA======================\n");
    printf("Ban ro: %s\n", message);

// Encrypt
    start = clock();
    KeyInitialization(choice, Key, context);

    AesEncrypt(context, message, resultEncrypt);
    end = clock();
    calculationTime = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("\nThoi gian ma hoa: %.4fs", calculationTime);
//Decrypt
    start = clock();
    KeyInitialization(choice, Key, context);
    printf("\n======================GIAI MA======================");
    AesDecrypt(context, resultEncrypt, resultDecrypt);
    end = clock();
    calculationTime = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("\nThoi gian giai ma: %.4fs", calculationTime);
    printf("\n====================================");
    return 0;
}
