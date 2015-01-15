#ifndef YSF_CSERVER_H
#define YSF_CSERVER_H

class CNetGame;
class RakServer;
struct Packet;
class CVehicleSpawn;

#include "CTypes.h"
#include "Addresses.h"

#include <vector>
#include <set>

class CServer
{
public:
	CServer(eSAMPVersion version);
	~CServer();

	bool AddPlayer(int playerid);
	bool RemovePlayer(int playerid);

	void Process();

	bool OnPlayerStreamIn(WORD playerid, WORD forplayerid);
	bool OnPlayerStreamOut(WORD playerid, WORD forplayerid);

	void SetGravity_(float fGravity);
	float GetGravity_(void);

	void SetWeather_(BYTE byteWeather);
	BYTE GetWeather_(void);

	eSAMPVersion GetVersion() { return m_Version; }
	
	void AllowNickNameCharacter(char character, bool enable);
	bool IsNickNameCharacterAllowed(char character);
	bool IsValidNick(char *szName);

	WORD GetMaxPlayers_();
	WORD GetPlayerCount();
	WORD GetNPCCount();

	void Packet_StatsUpdate(Packet *p);

	char*	GetStringVariable(char *szRule);
	void	SetStringVariable(char *szRule, char *szString);

	float	GetFloatVariable(char *szRule);
	void	SetFloatVariable(char *szRule, float value);

	int		GetIntVariable(char *szRule);
	void	SetIntVariable(char *szRule, int value);

	bool	GetBoolVariable(char *szRule);
	void	SetBoolVariable(char *szRule, bool value);

	void	ModifyVariableFlags(char* pVarName, DWORD VarFlags);
	
	std::map<int, CVehicleSpawn> vehicleSpawnData;
private:
	eSAMPVersion m_Version;
	//float m_fGravity;
	//unsigned char m_byteWeather;
	int m_iTicks;

	std::vector <char> m_vecValidNameCharacters;
};

#endif