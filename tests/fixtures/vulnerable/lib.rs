// Deliberately vulnerable Anchor program used as a lint fixture.
// Every block is tagged with the rule that should fire on it.
// DO NOT DEPLOY.
use anchor_lang::prelude::*;

declare_id!("Vu1nerab1e1111111111111111111111111111111111");

#[program]
pub mod vault {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.balance += amount; // ASL006
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.balance = v.balance - amount; // ASL006
        Ok(())
    }

    pub fn set_fee(ctx: Context<SetFee>, fee: u64) -> Result<()> {
        ctx.accounts.config.fee = fee;
        Ok(())
    }

    pub fn derive(ctx: Context<Derive>, bump: u8) -> Result<()> {
        // ASL003: caller-chosen bump
        let _pda = Pubkey::create_program_address(&[b"vault", &[bump]], ctx.program_id)
            .map_err(|_| ProgramError::InvalidSeeds)?;
        Ok(())
    }
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub fee: u64,
}

#[account]
pub struct Profile {
    pub user: Pubkey,
    pub name: String,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    // ASL004: same seed shape as Profile in CreateProfile
    #[account(mut, seeds = [b"user", payer.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // ASL005: owner signs but vault.owner is never compared
    pub owner: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    // ASL002: no CHECK comment
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SetFee<'info> {
    // ASL001: authority is not a signer
    pub admin: AccountInfo<'info>,
    #[account(mut, has_one = admin)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
#[instruction(name: String, bump: u8)]
pub struct CreateProfile<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    // ASL003: user-supplied bump
    #[account(init, payer = payer, space = 8 + 32 + 4 + 32, seeds = [b"user", payer.key().as_ref()], bump = bump)]
    pub profile: Account<'info, Profile>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(first: String, last: String)]
pub struct Tag<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    // ASL004: two adjacent variable-length seeds; ASL003 note: hard-coded bump
    #[account(mut, seeds = [first.as_bytes(), last.as_bytes()], bump = 254)]
    pub profile: Account<'info, Profile>,
}

#[derive(Accounts)]
pub struct Derive<'info> {
    pub anyone: Signer<'info>,
}
