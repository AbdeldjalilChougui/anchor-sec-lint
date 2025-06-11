// The same program as ../vulnerable/lib.rs with every issue fixed.
// The linter must report nothing here.
use anchor_lang::prelude::*;

declare_id!("Fixed11111111111111111111111111111111111111");

#[error_code]
pub enum VaultError {
    Overflow,
}

#[program]
pub mod vault {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.balance = v.balance.checked_add(amount).ok_or(VaultError::Overflow)?;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.balance = v.balance.checked_sub(amount).ok_or(VaultError::Overflow)?;
        Ok(())
    }

    pub fn set_fee(ctx: Context<SetFee>, fee: u64) -> Result<()> {
        ctx.accounts.config.fee = fee;
        Ok(())
    }

    pub fn derive(ctx: Context<Derive>) -> Result<()> {
        let (_pda, _bump) = Pubkey::find_program_address(&[b"vault"], ctx.program_id);
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
    #[account(mut, seeds = [b"vault", payer.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub owner: Signer<'info>,
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    /// CHECK: only receives lamports; must be the vault owner.
    #[account(mut, address = owner.key())]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SetFee<'info> {
    pub admin: Signer<'info>,
    #[account(mut, has_one = admin)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
#[instruction(name: String)]
pub struct CreateProfile<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + 32 + 4 + 32, seeds = [b"profile", payer.key().as_ref()], bump)]
    pub profile: Account<'info, Profile>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(first: String)]
pub struct Tag<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [b"profile", payer.key().as_ref()], bump)]
    pub profile: Account<'info, Profile>,
}

#[derive(Accounts)]
pub struct Derive<'info> {
    pub anyone: Signer<'info>,
}
