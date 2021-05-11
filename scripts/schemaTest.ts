import * as mongoose from 'mongoose';
import { Schema, Document } from 'mongoose';
import { dbUri } from '../config/database';

export interface IUnirepState extends Document {
    currentEpoch: number
	  latestEpochGSTLeaves: [ string ]
	  latestEpochTreeLeaves: [ string ]
	  nullifiers: [ string ]
      addEpoch() : number 
  }

  const UnirepStateSchema: Schema = new Schema({
    currentEpoch:  { type: Number },
	  latestEpochGSTLeaves: { type: [] },
	  latestEpochTreeLeaves: { type: [] },
	  nullifiers: { type: [] },
  }, { collection: 'UnirepState' });


export class UnirepStateClass {
    public currentEpoch: number
    constructor(
        epoch
    ){
        this.currentEpoch = epoch
    }
    public addEpoch ()  {
        console.log((this.currentEpoch)+ 1)
        return (this.currentEpoch)+ 1
    }

}


UnirepStateSchema.loadClass(UnirepStateClass)
const UnirepState = mongoose.model<IUnirepState>('UnirepState', UnirepStateSchema);

(async function() {

    const db = await mongoose.connect(dbUri)

// console.log(newEpoch)
    const a = new UnirepState({
        currentEpoch: 3,
	    latestEpochGSTLeaves: [],
	    latestEpochTreeLeaves: [  ],
	    nullifiers: [  ],
    })

    const res = a.addEpoch()
    console.log(res)
    const savedPost: IUnirepState = await a.save()
    db.disconnect()
})