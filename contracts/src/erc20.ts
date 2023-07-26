import {
  ProvablePure,
  Bool,
  CircuitString,
  provablePure,
  DeployArgs,
  Field,
  method,
  AccountUpdate,
  PublicKey,
  SmartContract,
  UInt64,
  Account,
  Experimental,
  Permissions,
  Mina,
  Int64,
  VerificationKey,
  state,
  State,
  Poseidon,
  MerkleTree,
  MerkleWitness,
  Struct,
} from 'snarkyjs';

class MyMerkleWitness extends MerkleWitness(8) {}

class Allowance extends Struct({
  owner: PublicKey,
  spender: PublicKey,
  value: UInt64,
}) {
  hash(): Field {
    return Poseidon.hash(Allowance.toFields(this));
  }
}

// we need the initiate tree root in order to tell the contract about our off-chain storage
let initialCommitment: Field = Field(0);

const tokenSymbol = 'FT';

/**
 * ERC-20 token standard.
 * https://ethereum.org/en/developers/docs/standards/tokens/erc-20/
 */
type Erc20 = {
  // pure view functions which don't need @method
  name?: () => CircuitString;
  symbol?: () => CircuitString;
  decimals?: () => Field; // TODO: should be UInt8 which doesn't exist yet
  totalSupply(): UInt64;
  balanceOf(owner: PublicKey): UInt64;
  allowance(owner: PublicKey, spender: PublicKey, path: MyMerkleWitness): UInt64;

  // mutations which need @method
  mint(account: PublicKey, amount: UInt64): Bool;
  burn(amount: UInt64): Bool;
  transfer(to: PublicKey, value: UInt64): Bool; // emits "Transfer" event
  transferFrom(from: PublicKey, to: PublicKey, value: UInt64): Bool; // emits "Transfer" event
  approveSpend(spender: PublicKey, value: UInt64, path: MyMerkleWitness): Bool; // emits "Approval" event
  increaseAllowance(spender: PublicKey, addedValue: UInt64, path: MyMerkleWitness): Bool; // emits "Approval" event
  decreaseAllowance(spender: PublicKey, subtractedValue: UInt64, path: MyMerkleWitness): Bool; // emits "Approval" event

  // events
  events: {
    Transfer: ProvablePure<{
      from: PublicKey;
      to: PublicKey;
      value: UInt64;
    }>;
    Approval: ProvablePure<{
      owner: PublicKey;
      spender: PublicKey;
      value: UInt64;
    }>;
  };
};

/**
 * A simple ERC20 token
 *
 * Tokenomics:
 * The supply is constant and the entire supply is initially sent to an account controlled by the zkApp developer
 * After that, tokens can be sent around with authorization from their owner, but new ones can't be minted.
 *
 * Functionality:
 * Just enough to be swapped by the DEX contract, and be secure
 */
export class FungibleToken extends SmartContract implements Erc20 {
  @state(UInt64) totalAmountInCirculation = State<UInt64>();
  @state(Field) commitment = State<Field>();

  deploy(args: DeployArgs) {
    super.deploy(args);

    const permissionToEdit = Permissions.proof();

    this.account.permissions.set({
      ...Permissions.default(),
      editState: permissionToEdit,
      setTokenSymbol: permissionToEdit,
      send: permissionToEdit,
      receive: permissionToEdit,
    });
  }

  @method init() {
    super.init();
    this.account.tokenSymbol.set(tokenSymbol);
    this.totalAmountInCirculation.set(UInt64.zero);
    this.commitment.set(initialCommitment);
  }

  // ERC20 API
  name(): CircuitString {
    return CircuitString.fromString('FungibleToken');
  }
  symbol(): CircuitString {
    return CircuitString.fromString(tokenSymbol);
  }
  decimals(): Field {
    return Field(18);
  }
  totalSupply(): UInt64 {
    return this.totalAmountInCirculation.get();
  }
  balanceOf(owner: PublicKey): UInt64 {
    let account = Account(owner, this.token.id);
    let balance = account.balance.get();
    account.balance.assertEquals(balance);
    return balance;
  }
  allowance(owner: PublicKey, spender: PublicKey, path: MyMerkleWitness): UInt64 {
    Allowance.get('Bob')?.value;
    return UInt64.zero;
  }

  @method mint(account: PublicKey, amount: UInt64) {
    let totalAmountInCirculation = this.totalAmountInCirculation.get();
    this.totalAmountInCirculation.assertEquals(totalAmountInCirculation);
    let newTotalAmountInCirculation = totalAmountInCirculation.add(amount);
    this.token.mint({ address: account, amount });
    this.totalAmountInCirculation.set(newTotalAmountInCirculation);
    return Bool(true);
  }
  @method burn(amount: UInt64): Bool {
    let totalAmountInCirculation = this.totalAmountInCirculation.get();
    this.totalAmountInCirculation.assertEquals(totalAmountInCirculation);
    let newTotalAmountInCirculation = totalAmountInCirculation.sub(amount);
    this.token.burn({ address: this.sender, amount });
    this.totalAmountInCirculation.set(newTotalAmountInCirculation);
    return Bool(true);
  }
  @method transfer(to: PublicKey, value: UInt64): Bool {
    this.token.send({ from: this.sender, to, amount: value });
    this.emitEvent('Transfer', { from: this.sender, to, value });
    // we don't have to check the balance of the sender -- this is done by the zkApp protocol
    return Bool(true);
  }
  @method transferFrom(from: PublicKey, to: PublicKey, value: UInt64): Bool {
    this.allowance(from, this.sender, witness).assertGreaterThanOrEqual(value);
    this.token.send({ from, to, amount: value });
    this.emitEvent('Transfer', { from, to, value });
    // we don't have to check the balance of the sender -- this is done by the zkApp protocol
    return Bool(true);
  }
  @method approveSpend(spender: PublicKey, value: UInt64, path: MyMerkleWitness): Bool {
    // we update the account and approve spend
    let newAllowance = new Allowance({ owner: this.sender, spender, value });
    // we calculate the new Merkle Root, based on the account changes
    let newCommitment = path.calculateRoot(newAllowance.hash());
    this.commitment.set(newCommitment);
    this.emitEvent('Approval', { owner: this.sender, spender, value });
    return Bool(true);
  }
  @method increaseAllowance(spender: PublicKey, addedValue: UInt64, path: MyMerkleWitness): Bool {
    let currentValue = this.allowance(this.sender, spender, witness);
    this.approveSpend(spender, currentValue.add(addedValue), path);
    return Bool(true);
  }
  @method decreaseAllowance(spender: PublicKey, subtractedValue: UInt64, path: MyMerkleWitness): Bool {
    let currentValue = this.allowance(this.sender, spender, witness);
    this.approveSpend(spender, currentValue.sub(subtractedValue), path);
    return Bool(true);
  }

  events = {
    Transfer: provablePure({
      from: PublicKey,
      to: PublicKey,
      value: UInt64,
    }),
    Approval: provablePure({
      owner: PublicKey,
      spender: PublicKey,
      value: UInt64,
    }),
  };

  // additional API needed for zkApp token accounts

  @method transferFromZkapp(
    from: PublicKey,
    to: PublicKey,
    value: UInt64,
    approve: Experimental.Callback<any>
  ): Bool {
    // TODO: need to be able to witness a certain layout of account updates, in this case
    // tokenContract --> sender --> receiver
    let fromUpdate = this.approve(approve, AccountUpdate.Layout.NoChildren);

    let negativeAmount = Int64.fromObject(fromUpdate.body.balanceChange);
    negativeAmount.assertEquals(Int64.from(value).neg());
    let tokenId = this.token.id;
    fromUpdate.body.tokenId.assertEquals(tokenId);
    fromUpdate.body.publicKey.assertEquals(from);

    let toUpdate = AccountUpdate.create(to, tokenId);
    toUpdate.balance.addInPlace(value);
    this.emitEvent('Transfer', { from, to, value });
    return Bool(true);
  }

  // this is a very standardized deploy method. instead, we could also take the account update from a callback
  @method deployZkapp(
    zkappAddress: PublicKey,
    verificationKey: VerificationKey
  ) {
    let tokenId = this.token.id;
    let zkapp = Experimental.createChildAccountUpdate(
      this.self,
      zkappAddress,
      tokenId
    );
    zkapp.account.permissions.set(Permissions.default());
    zkapp.account.verificationKey.set(verificationKey);
    zkapp.requireSignature();
  }

  // for letting a zkapp do whatever it wants, as long as no tokens are transfered
  // TODO: atm, we have to restrict the zkapp to have no children
  //       -> need to be able to witness a general layout of account updates
  @method approveZkapp(callback: Experimental.Callback<any>) {
    let zkappUpdate = this.approve(callback, AccountUpdate.Layout.NoChildren);
    Int64.fromObject(zkappUpdate.body.balanceChange).assertEquals(UInt64.zero);
  }
}
